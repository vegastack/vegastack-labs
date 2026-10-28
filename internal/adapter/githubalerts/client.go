// Package githubalerts delivers a fixed sanitized projection, never local alert authority.
package githubalerts

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/operations"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var ErrUnavailable = errors.New("github alert delivery unavailable")
var repoPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$`)

type Borrow func(context.Context, string, string) (*credentialref.Value, error)
type Client struct {
	base, repository, target string
	repositoryID             int64
	http                     *http.Client
	borrow                   Borrow
}

func New(base, repository string, repositoryID int64, transport http.RoundTripper, borrow Borrow) (*Client, error) {
	u, e := url.Parse(base)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" || !repoPattern.MatchString(repository) || strings.Contains(repository, "..") || repositoryID <= 0 || borrow == nil {
		return nil, ErrUnavailable
	}
	if transport == nil {
		transport = &http.Transport{Proxy: nil, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second}
	}
	return &Client{base: base, repository: repository, repositoryID: repositoryID, target: operations.Digest(repository), borrow: borrow, http: &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func (c *Client) request(ctx context.Context, token []byte, method, path string, body any, out any) error {
	var raw []byte
	var e error
	if body != nil {
		raw, e = json.Marshal(body)
		if e != nil {
			return ErrUnavailable
		}
	}
	r, e := http.NewRequestWithContext(ctx, method, c.base+path, bytes.NewReader(raw))
	if e != nil {
		return ErrUnavailable
	}
	r.Header.Set("Authorization", "Bearer "+string(token))
	r.Header.Set("Accept", "application/vnd.github+json")
	r.Header.Set("X-GitHub-Api-Version", "2026-03-10")
	r.Header.Set("Content-Type", "application/json")
	res, e := c.http.Do(r)
	if e != nil {
		return ErrUnavailable
	}
	defer res.Body.Close()
	if res.StatusCode != 200 && res.StatusCode != 201 {
		return ErrUnavailable
	}
	raw, e = io.ReadAll(io.LimitReader(res.Body, 1048577))
	if e != nil || len(raw) > 1048576 || json.Unmarshal(raw, out) != nil {
		return ErrUnavailable
	}
	return nil
}

// Deliver searches the fixed repository before creating, including closed issues,
// so an uncertain create/restart retries the same correlation instead of opening
// a second issue. Incomplete bounded lookup fails closed. The store serializes it.
func (c *Client) Deliver(ctx context.Context, event audit.Event) error {
	if event.Type != "operations.alert.opened" && event.Type != "operations.alert.closed" || event.Target.Kind != "operations-target" || !strings.HasPrefix(event.CorrelationID, "operations-") || !regexp.MustCompile(`^operations-[a-f0-9]{32}$`).MatchString(event.CorrelationID) || !regexp.MustCompile(`^sha256:[a-f0-9]{64}$`).MatchString(event.Target.ID) {
		return ErrUnavailable
	}
	if _, _, e := audit.CanonicalEvent(event); e != nil {
		return ErrUnavailable
	}
	v, e := c.borrow(ctx, "operations.github-issues.write", c.target)
	if e != nil || v == nil {
		return ErrUnavailable
	}
	defer v.Close()
	token := v.Bytes()
	if len(token) == 0 || len(token) > 8192 {
		return ErrUnavailable
	}
	path := "/repos/" + c.repository
	var repo struct {
		ID       int64  `json:"id"`
		FullName string `json:"full_name"`
	}
	if e = c.request(ctx, token, "GET", path, nil, &repo); e != nil || repo.ID != c.repositoryID || repo.FullName != c.repository {
		return ErrUnavailable
	}
	marker := "<!-- vsk-alert:" + event.CorrelationID + " -->"
	number := int64(0)
	complete := false
	for page := 1; page <= 10; page++ {
		var issues []struct {
			Number      int64           `json:"number"`
			Body        string          `json:"body"`
			PullRequest json.RawMessage `json:"pull_request"`
		}
		if e = c.request(ctx, token, "GET", fmt.Sprintf("%s/issues?state=all&per_page=100&page=%d", path, page), nil, &issues); e != nil {
			return e
		}
		for _, issue := range issues {
			if len(issue.PullRequest) == 0 && strings.HasPrefix(issue.Body, marker+"\n") {
				if issue.Number <= 0 || number != 0 {
					return ErrUnavailable
				}
				number = issue.Number
			}
		}
		if len(issues) < 100 {
			complete = true
			break
		}
	}
	if !complete {
		return ErrUnavailable
	}
	state := "open"
	if event.Type == "operations.alert.closed" {
		state = "closed"
	}
	body := marker + "\nOperational alert: " + state + "\nTarget fingerprint: " + event.Target.ID + "\nEvent: " + fmt.Sprint(event.EventID) + "\nObserved: " + event.OccurredAt + "\nRunbook: docs/security-and-operations.md\nLocal SQLite remains authoritative."
	// Reborrow after the read phase so current gate, epoch and reference state
	// are rechecked immediately before the provider mutation.
	latest, e := c.borrow(ctx, "operations.github-issues.write", c.target)
	if e != nil || latest == nil {
		return ErrUnavailable
	}
	defer latest.Close()
	token = latest.Bytes()
	if len(token) == 0 || len(token) > 8192 {
		return ErrUnavailable
	}
	request := map[string]any{"title": "VegaStack operational alert " + event.CorrelationID, "body": body, "state": state}
	var response struct {
		Number int64  `json:"number"`
		State  string `json:"state"`
	}
	if number == 0 {
		if state == "closed" {
			return ErrUnavailable
		}
		delete(request, "state")
		e = c.request(ctx, token, "POST", path+"/issues", request, &response)
	} else {
		e = c.request(ctx, token, "PATCH", fmt.Sprintf("%s/issues/%d", path, number), request, &response)
	}
	if e != nil || response.Number <= 0 || number != 0 && response.Number != number || response.State != state {
		return ErrUnavailable
	}
	return nil
}
