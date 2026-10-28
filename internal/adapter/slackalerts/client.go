// Package slackalerts sends only fixed readiness canaries to a protected Slack webhook.
package slackalerts

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
)

var ErrUnavailable = errors.New("slack notification canary unavailable")

var (
	webhookPath = regexp.MustCompile(`^/services/[A-Z0-9]+/[A-Z0-9]+/[A-Za-z0-9_-]+$`)
	correlation = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
	digest      = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
)

// Receipt records provider acceptance, not human receipt or message readership.
type Receipt struct {
	AcceptedAt     time.Time
	ResponseDigest string
}

type Client struct {
	http  *http.Client
	clock func() time.Time
}

func NewClient(transport http.RoundTripper, clock func() time.Time) *Client {
	if transport == nil {
		transport = &http.Transport{Proxy: nil, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second}
	}
	if clock == nil {
		clock = time.Now
	}
	return &Client{http: &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, clock: clock}
}

// SendCanary borrows the caller-owned webhook for one attempt without retries.
// The caller binds the route and credential to an acknowledged exact plan;
// check must revalidate that authority immediately before the HTTP mutation.
// See https://docs.slack.dev/messaging/sending-messages-using-incoming-webhooks/.
func (c *Client) SendCanary(ctx context.Context, webhook *credentialref.Value, correlationID, phase, routeDigest string, check func() error) (Receipt, error) {
	if c == nil || c.http == nil || c.clock == nil || check == nil || !correlation.MatchString(correlationID) || !digest.MatchString(routeDigest) || phase != "failure" && phase != "recovery" {
		return Receipt{}, ErrUnavailable
	}
	raw := webhook.Bytes()
	if len(raw) == 0 || len(raw) > 4096 {
		return Receipt{}, ErrUnavailable
	}
	u, err := url.Parse(string(raw))
	if err != nil || u.Scheme != "https" || u.Host != "hooks.slack.com" || u.User != nil || u.Opaque != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || !webhookPath.MatchString(u.Path) {
		return Receipt{}, ErrUnavailable
	}
	payload, err := json.Marshal(struct {
		Text string `json:"text"`
	}{Text: "VegaStack notification readiness test: " + phase + ". This is a test, not an infrastructure incident.\nCorrelation: " + correlationID + "\nRoute fingerprint: " + routeDigest})
	if err != nil {
		return Receipt{}, ErrUnavailable
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(payload))
	if err != nil {
		return Receipt{}, ErrUnavailable
	}
	req.Header.Set("Content-Type", "application/json")
	if check() != nil {
		return Receipt{}, ErrUnavailable
	}
	response, err := c.http.Do(req)
	if err != nil {
		return Receipt{}, ErrUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return Receipt{}, ErrUnavailable
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 1025))
	if err != nil || len(body) > 1024 || strings.TrimSpace(string(body)) != "ok" {
		return Receipt{}, ErrUnavailable
	}
	accepted := c.clock().UTC()
	if accepted.IsZero() {
		return Receipt{}, ErrUnavailable
	}
	sum := sha256.Sum256(body)
	return Receipt{AcceptedAt: accepted, ResponseDigest: "sha256:" + hex.EncodeToString(sum[:])}, nil
}
