package slackalerts

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
)

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

const syntheticWebhook = "https://hooks.slack.com/services/T00000000/B00000000/syntheticFixtureOnly"

func TestCanaryFixedPayloadAndAcceptance(t *testing.T) {
	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	route := "sha256:" + strings.Repeat("a", 64)
	for _, phase := range []string{"failure", "recovery"} {
		t.Run(phase, func(t *testing.T) {
			checked, calls := false, 0
			client := NewClient(transportFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				if !checked || req.Method != "POST" || req.URL.String() != syntheticWebhook || req.Header.Get("Content-Type") != "application/json" {
					t.Fatal("request escaped fixed authority or transport")
				}
				raw, _ := io.ReadAll(req.Body)
				var payload map[string]string
				if json.Unmarshal(raw, &payload) != nil || len(payload) != 1 || !strings.Contains(payload["text"], "test: "+phase) || !strings.Contains(payload["text"], route) || strings.Contains(string(raw), "syntheticFixtureOnly") {
					t.Fatal("wrong or credential-bearing message")
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("ok")), Header: http.Header{}}, nil
			}), func() time.Time { return now })
			value, _ := credentialref.NewValue([]byte(syntheticWebhook))
			defer value.Close()
			receipt, err := client.SendCanary(context.Background(), value, "canary-123", phase, route, func() error { checked = true; return nil })
			if err != nil || calls != 1 || !receipt.AcceptedAt.Equal(now) || !digest.MatchString(receipt.ResponseDigest) {
				t.Fatal(receipt, err, calls)
			}
		})
	}
}

func TestCanaryRejectsWrongRouteAndStaleAuthorityBeforeSend(t *testing.T) {
	calls := 0
	client := NewClient(transportFunc(func(*http.Request) (*http.Response, error) { calls++; return nil, errors.New("unexpected send") }), time.Now)
	route := "sha256:" + strings.Repeat("b", 64)
	for _, endpoint := range []string{
		"http://hooks.slack.com/services/T0/B0/fixture", "https://hooks.slack.com.evil.example/services/T0/B0/fixture",
		"https://hooks.slack.com:443/services/T0/B0/fixture", "https://user@hooks.slack.com/services/T0/B0/fixture",
		syntheticWebhook + "?secret=fixture", syntheticWebhook + "#fragment", syntheticWebhook + "?",
		"https://hooks.slack.com/services/T0/B0/%66ixture", "https://hooks.slack.com/services/T0/B0/../fixture",
	} {
		value, _ := credentialref.NewValue([]byte(endpoint))
		_, err := client.SendCanary(context.Background(), value, "canary-123", "failure", route, func() error { return nil })
		value.Close()
		if !errors.Is(err, ErrUnavailable) || calls != 0 {
			t.Fatal("unapproved route contacted")
		}
	}
	value, _ := credentialref.NewValue([]byte(syntheticWebhook))
	defer value.Close()
	for _, check := range []func() error{nil, func() error { return errors.New("private stale authority detail") }} {
		_, err := client.SendCanary(context.Background(), value, "canary-123", "failure", route, check)
		if !errors.Is(err, ErrUnavailable) || calls != 0 {
			t.Fatal("missing or stale authority sent")
		}
	}
	value.Close()
	if _, err := client.SendCanary(context.Background(), value, "canary-123", "failure", route, func() error { return nil }); err == nil || calls != 0 {
		t.Fatal("closed credential sent")
	}
}

func TestCanaryDoesNotRetryRedirectLeakOrInventReceipt(t *testing.T) {
	for _, fixture := range []struct {
		name string
		code int
		body string
		err  error
	}{
		{"redirect", 307, "ok", nil}, {"rate-limit", 429, "private-provider-detail", nil},
		{"rejected", 200, "invalid_token private-provider-detail", nil}, {"oversized", 200, strings.Repeat(" ", 1025) + "ok", nil},
		{"transport", 0, "", errors.New(syntheticWebhook)},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			calls := 0
			client := NewClient(transportFunc(func(*http.Request) (*http.Response, error) {
				calls++
				if fixture.err != nil {
					return nil, fixture.err
				}
				return &http.Response{StatusCode: fixture.code, Header: http.Header{"Location": []string{"https://other.example"}}, Body: io.NopCloser(strings.NewReader(fixture.body))}, nil
			}), time.Now)
			value, _ := credentialref.NewValue([]byte(syntheticWebhook))
			defer value.Close()
			receipt, err := client.SendCanary(context.Background(), value, "canary-123", "failure", "sha256:"+strings.Repeat("c", 64), func() error { return nil })
			if err != ErrUnavailable || receipt != (Receipt{}) || calls != 1 || strings.Contains(err.Error(), "private") || strings.Contains(err.Error(), "https:") {
				t.Fatal("uncertain delivery leaked, retried or fabricated receipt", receipt, err, calls)
			}
		})
	}
}
