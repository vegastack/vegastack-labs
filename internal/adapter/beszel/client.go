// Package beszel implements only exact configured system reads, never fleet enumeration.
package beszel

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/operations"
	"github.com/vegastack/vegastack-labs/internal/readmodel"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"time"
)

var ErrUnavailable = errors.New("beszel observation unavailable")
var idPattern = regexp.MustCompile(`^[a-z0-9]{15}$`)

type Borrow func(context.Context, string, string) (*credentialref.Value, error)
type Client struct {
	base   string
	http   *http.Client
	borrow Borrow
}

func New(base string, transport http.RoundTripper, borrow Borrow) (*Client, error) {
	u, e := url.Parse(base)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || borrow == nil {
		return nil, ErrUnavailable
	}
	if transport == nil {
		transport = &http.Transport{Proxy: nil, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second}
	}
	return &Client{base: base, borrow: borrow, http: &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

// Observe requires a preconfigured exact record; unknown/provider outage cannot
// become healthy. Updated is the provider record timestamp, not a metrics sample.
func (c *Client) Observe(ctx context.Context, recordID, targetDigest string, now time.Time, staleAfter time.Duration) (operations.Observation, error) {
	o := operations.Observation{TargetDigest: targetDigest, Class: "source-health", Severity: "critical", State: readmodel.SourceUnknown, ObservedAt: now.UTC()}
	if !regexp.MustCompile(`^sha256:[a-f0-9]{64}$`).MatchString(targetDigest) || !idPattern.MatchString(recordID) || staleAfter <= 0 || now.IsZero() {
		return o, ErrUnavailable
	}
	value, e := c.borrow(ctx, "operations.beszel.read", targetDigest)
	if e != nil || value == nil {
		return o, ErrUnavailable
	}
	defer value.Close()
	token := value.Bytes()
	if len(token) == 0 || len(token) > 8192 {
		return o, ErrUnavailable
	}
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/api/collections/systems/records/"+recordID+"?fields=id,status,updated", nil)
	if e != nil {
		return o, ErrUnavailable
	}
	req.Header.Set("Authorization", string(token))
	res, e := c.http.Do(req)
	if e != nil {
		return o, ErrUnavailable
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return o, ErrUnavailable
	}
	raw, e := io.ReadAll(io.LimitReader(res.Body, 65537))
	if e != nil || len(raw) > 65536 {
		return o, ErrUnavailable
	}
	var data struct {
		ID      string `json:"id"`
		Status  string `json:"status"`
		Updated string `json:"updated"`
	}
	if json.Unmarshal(raw, &data) != nil || data.ID != recordID {
		return o, ErrUnavailable
	}
	updated, e := time.Parse("2006-01-02 15:04:05.000Z", data.Updated)
	if e != nil {
		updated, e = time.Parse(time.RFC3339Nano, data.Updated)
	}
	if e != nil || updated.After(now) {
		return o, ErrUnavailable
	}
	if now.Sub(updated) > staleAfter {
		o.State = readmodel.SourceStale
		return o, nil
	}
	switch data.Status {
	case "up":
		o.State = readmodel.SourceHealthy
		o.Verified = true
		o.SampleAt = updated
	case "down":
		o.State = readmodel.SourceFailed
	case "paused", "pending":
		o.State = readmodel.SourceUnknown
	default:
		return o, ErrUnavailable
	}
	return o, nil
}
