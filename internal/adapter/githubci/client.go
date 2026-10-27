// Package githubci provides inert read-only observations using the GitHub REST
// 2022-11-28 contract. Observations do not admit a job or authorize execution.
package githubci

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/ci"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/strictjson"
)

const maxBody = 1 << 20
const maxWorkflow = 512 << 10

var (
	ErrInput       = failure.New(generated.ErrorCodeInputInvalid, "github-ci-observation", false)
	ErrIdentity    = failure.New(generated.ErrorCodeIntegrityFailure, "github-ci-observation", false)
	ErrUnavailable = failure.New(generated.ErrorCodeDependencyUnavailable, "github-ci-observation", false)
	repositoryName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_][A-Za-z0-9_.-]{0,99}$`)
	workflowPath   = regexp.MustCompile(`^\.github/workflows/[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}\.ya?ml$`)
)

type Client struct {
	base string
	http *http.Client
}
type Target struct {
	Enrollment   ci.Enrollment
	RunID, JobID string
	Attempt      uint32
}

// NewClient accepts only a protected, configured HTTPS API origin (or fixed
// enterprise API prefix). The injected transport is trusted composition.
func NewClient(baseURL string, transport http.RoundTripper) (*Client, error) {
	u, e := url.Parse(baseURL)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" || strings.ContainsAny(u.Path, "\\\r\n") {
		return nil, ErrInput
	}
	for _, s := range strings.Split(u.Path, "/") {
		if s == "." || s == ".." {
			return nil, ErrInput
		}
	}
	if transport == nil {
		transport = &http.Transport{Proxy: nil, ForceAttemptHTTP2: true, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second, IdleConnTimeout: 30 * time.Second, DisableKeepAlives: true}
	}
	return &Client{base: strings.TrimRight(u.String(), "/"), http: &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func positiveID(s string) int64 {
	n, e := strconv.ParseInt(s, 10, 64)
	if e != nil || n <= 0 || strconv.FormatInt(n, 10) != s {
		return 0
	}
	return n
}

type repository struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	FullName string `json:"full_name"`
	Owner    struct {
		ID    int64  `json:"id"`
		Login string `json:"login"`
	} `json:"owner"`
}

func (r repository) matches(b ci.Binding) bool {
	parts := strings.Split(b.Repository, "/")
	return len(parts) == 2 && r.ID == positiveID(b.RepositoryID) && r.Owner.ID == positiveID(b.OwnerID) && r.FullName == b.Repository && r.Name == parts[1] && r.Owner.Login == parts[0]
}

type run struct {
	ID             int64      `json:"id"`
	Attempt        uint32     `json:"run_attempt"`
	WorkflowID     int64      `json:"workflow_id"`
	Path           string     `json:"path"`
	SHA            string     `json:"head_sha"`
	Branch         string     `json:"head_branch"`
	Event          string     `json:"event"`
	Status         string     `json:"status"`
	Repository     repository `json:"repository"`
	HeadRepository repository `json:"head_repository"`
}

func (r run) matches(t Target) bool {
	b := t.Enrollment.Binding
	return r.ID == positiveID(t.RunID) && r.Attempt == t.Attempt && r.WorkflowID == positiveID(b.WorkflowID) && (r.Path == b.WorkflowPath || r.Path == b.WorkflowPath+"@"+b.Ref) && r.SHA == b.Revision && r.Branch == strings.TrimPrefix(b.Ref, "refs/heads/") && r.Event == b.Event && r.Status == "in_progress" && r.Repository.matches(b) && r.HeadRepository.matches(b)
}

type job struct {
	ID       int64    `json:"id"`
	RunID    int64    `json:"run_id"`
	SHA      string   `json:"head_sha"`
	Name     string   `json:"name"`
	Status   string   `json:"status"`
	RunnerID int64    `json:"runner_id"`
	GroupID  int64    `json:"runner_group_id"`
	Labels   []string `json:"labels"`
}

func (j job) matches(t Target) bool {
	b := t.Enrollment.Binding
	a := slices.Clone(j.Labels)
	e := slices.Clone(b.Labels)
	slices.Sort(a)
	slices.Sort(e)
	return j.ID == positiveID(t.JobID) && j.RunID == positiveID(t.RunID) && j.SHA == b.Revision && j.Name == b.JobName && j.Status == "in_progress" && j.RunnerID == positiveID(b.RunnerID) && j.GroupID == positiveID(b.RunnerGroupID) && slices.Equal(a, e)
}

// Observe uses only constructed routes; it never follows response URLs. Nil
// credentials explicitly select public reads, without consulting environment.
func (c *Client) Observe(ctx context.Context, t Target, v *credentialref.Value) (ci.Observation, error) {
	return c.observe(ctx, t, v, nil)
}
func (c *Client) observe(ctx context.Context, t Target, v *credentialref.Value, check func() error) (ci.Observation, error) {
	empty := ci.Observation{}
	b := t.Enrollment.Binding
	if ctx == nil || c == nil || c.http == nil || ci.ValidateEnrollment(t.Enrollment) != nil || !repositoryName.MatchString(b.Repository) || !workflowPath.MatchString(b.WorkflowPath) || strings.Contains(b.WorkflowPath, "..") || t.Attempt == 0 {
		return empty, ErrInput
	}
	for _, s := range []string{t.RunID, t.JobID, b.RepositoryID, b.OwnerID, b.WorkflowID, b.RunnerID, b.RunnerGroupID} {
		if positiveID(s) == 0 {
			return empty, ErrInput
		}
	}
	if v != nil {
		token := v.Bytes()
		if len(token) == 0 || len(token) > 4096 || strings.TrimSpace(string(token)) != string(token) || strings.ContainsAny(string(token), "\r\n\x00") {
			return empty, ErrInput
		}
	}
	// One total observation deadline also bounds multi-page slow responses.
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	prefix := "/repos/" + b.Repository
	current := prefix + "/actions/runs/" + t.RunID
	var repo repository
	if e := c.getChecked(ctx, prefix, v, &repo, check); e != nil {
		return empty, e
	}
	if !repo.matches(b) {
		return empty, ErrIdentity
	}
	readRun := func(path string) error {
		var r run
		if e := c.getChecked(ctx, path, v, &r, check); e != nil {
			return e
		}
		if !r.matches(t) {
			return ErrIdentity
		}
		return nil
	}
	if e := readRun(current); e != nil {
		return empty, e
	}
	attempt := current + "/attempts/" + strconv.FormatUint(uint64(t.Attempt), 10)
	if e := readRun(attempt); e != nil {
		return empty, e
	}
	if e := c.jobsChecked(ctx, attempt+"/jobs", t, v, check); e != nil {
		return empty, e
	}
	if e := c.workflowChecked(ctx, prefix+"/contents/"+b.WorkflowPath+"?ref="+url.QueryEscape(b.Revision), b, v, check); e != nil {
		return empty, e
	}
	if e := readRun(current); e != nil {
		return empty, e
	}
	// Return expected, verified values only, never arbitrary provider strings.
	b.Labels = slices.Clone(b.Labels)
	return ci.Observation{Binding: b, HeadRepositoryID: b.RepositoryID, RunID: t.RunID, JobID: t.JobID, Attempt: t.Attempt, RunStatus: "in_progress", JobStatus: "in_progress", ObservedAt: time.Now().UTC()}, nil
}
func (c *Client) jobs(ctx context.Context, path string, t Target, v *credentialref.Value) error {
	return c.jobsChecked(ctx, path, t, v, nil)
}
func (c *Client) jobsChecked(ctx context.Context, path string, t Target, v *credentialref.Value, check func() error) error {
	jobs, err := c.listJobs(ctx, path, t, v, check)
	if err != nil {
		return err
	}
	if check != nil {
		owned := 0
		for _, j := range jobs {
			if j.RunnerID == positiveID(t.Enrollment.Binding.RunnerID) {
				owned++
				if !j.matches(t) {
					return ErrIdentity
				}
			}
		}
		if owned != 1 {
			return ErrIdentity
		}
	}
	for _, j := range jobs {
		if j.ID == positiveID(t.JobID) {
			if !j.matches(t) {
				return ErrIdentity
			}
			return nil
		}
	}
	return ErrIdentity
}
func (c *Client) listJobs(ctx context.Context, path string, t Target, v *credentialref.Value, check func() error) ([]job, error) {
	seen := map[int64]bool{}
	total := -1
	all := []job{}
	for page := 1; page <= 10; page++ {
		var result struct {
			Count *int  `json:"total_count"`
			Jobs  []job `json:"jobs"`
		}
		if e := c.getChecked(ctx, path+"?page="+strconv.Itoa(page)+"&per_page=100", v, &result, check); e != nil {
			return nil, e
		}
		if result.Count == nil || *result.Count < 1 || *result.Count > 1000 || len(result.Jobs) > 100 {
			return nil, ErrIdentity
		}
		if total < 0 {
			total = *result.Count
		}
		if total != *result.Count || len(result.Jobs) != min(100, total-len(seen)) {
			return nil, ErrIdentity
		}
		for _, j := range result.Jobs {
			if j.ID <= 0 || seen[j.ID] || j.RunID != positiveID(t.RunID) || j.SHA != t.Enrollment.Binding.Revision {
				return nil, ErrIdentity
			}
			seen[j.ID] = true
			all = append(all, j)
		}
		if len(seen) == total {
			return all, nil
		}
	}
	return nil, ErrIdentity
}
func (c *Client) workflow(ctx context.Context, path string, b ci.Binding, v *credentialref.Value) error {
	return c.workflowChecked(ctx, path, b, v, nil)
}
func (c *Client) workflowChecked(ctx context.Context, path string, b ci.Binding, v *credentialref.Value, check func() error) error {
	var f struct {
		Type     string `json:"type"`
		Path     string `json:"path"`
		Size     *int   `json:"size"`
		Encoding string `json:"encoding"`
		Content  string `json:"content"`
		SHA      string `json:"sha"`
	}
	if e := c.getChecked(ctx, path, v, &f, check); e != nil {
		return e
	}
	if f.Type != "file" || f.Path != b.WorkflowPath || f.Encoding != "base64" || f.Size == nil || *f.Size < 1 || *f.Size > maxWorkflow {
		return ErrIdentity
	}
	raw, e := base64.StdEncoding.Strict().DecodeString(f.Content)
	if e != nil || len(raw) != *f.Size {
		return ErrIdentity
	}
	digest := sha256.Sum256(raw)
	if "sha256:"+hex.EncodeToString(digest[:]) != b.WorkflowDigest {
		return ErrIdentity
	}
	if f.SHA != "" {
		blob := sha1.New()
		fmt.Fprintf(blob, "blob %d\x00", len(raw))
		blob.Write(raw)
		if hex.EncodeToString(blob.Sum(nil)) != f.SHA {
			return ErrIdentity
		}
	}
	return nil
}
func (c *Client) get(ctx context.Context, path string, v *credentialref.Value, out any) error {
	return c.getChecked(ctx, path, v, out, nil)
}
func (c *Client) getChecked(ctx context.Context, path string, v *credentialref.Value, out any, check func() error) error {
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)
	if e != nil {
		return ErrInput
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if v != nil {
		req.Header.Set("Authorization", "Bearer "+string(v.Bytes()))
	}
	if check != nil {
		if e := checked(ctx, check); e != nil {
			return e
		}
	}
	res, e := c.http.Do(req)
	if e != nil {
		return ErrUnavailable
	}
	defer res.Body.Close()
	switch res.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized:
		return failure.New(generated.ErrorCodeAuthenticationRequired, "github-ci-observation", false)
	case http.StatusForbidden:
		return failure.New(generated.ErrorCodeAuthorizationDenied, "github-ci-observation", false)
	case http.StatusNotFound:
		return failure.New(generated.ErrorCodeResourceNotFound, "github-ci-observation", false)
	case http.StatusTooManyRequests:
		return failure.New(generated.ErrorCodeRateLimited, "github-ci-observation", false)
	default:
		return ErrUnavailable
	}
	raw, e := io.ReadAll(io.LimitReader(res.Body, maxBody+1))
	if e != nil {
		return ErrUnavailable
	}
	trimmed := strings.TrimSpace(string(raw))
	if len(raw) > maxBody || len(trimmed) == 0 || trimmed[0] != '{' || strictjson.Scan(ctx, raw, strictjson.Limits{MaxDepth: 32}) != nil || json.Unmarshal(raw, out) != nil {
		return ErrIdentity
	}
	return nil
}
