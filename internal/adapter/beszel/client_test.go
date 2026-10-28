package beszel

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/operations"
	"github.com/vegastack/vegastack-labs/internal/readmodel"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestExactRecordScopeFreshnessAndSanitization(t *testing.T) {
	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	target := operations.Digest("private-host")
	body := `{"id":"abcdefghijklmno","status":"up","updated":"2026-10-28 11:59:59.000Z","name":"seeded-private-secret","host":"protected-provider-payload"}`
	code := 200
	calls := 0
	c, e := New("https://monitor.example", transportFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "GET" || r.URL.Path != "/api/collections/systems/records/abcdefghijklmno" || r.Header.Get("Authorization") != "seed-token" {
			t.Fatal("wrong read", r.Method, r.URL.Path)
		}
		return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}}, nil
	}), func(_ context.Context, p, s string) (*credentialref.Value, error) {
		if p != "operations.beszel.read" || s != target {
			t.Fatal("wrong credential scope")
		}
		return credentialref.NewValue([]byte("seed-token"))
	})
	if e != nil {
		t.Fatal(e)
	}
	o, e := c.Observe(context.Background(), "abcdefghijklmno", target, now, time.Minute)
	if e != nil || o.State != readmodel.SourceHealthy || !o.Verified {
		t.Fatal(o, e)
	}
	o, e = c.Observe(context.Background(), "abcdefghijklmno", target, now.Add(time.Hour), time.Minute)
	if e != nil || o.State != readmodel.SourceStale || o.Verified {
		t.Fatal(o, e)
	}
	code = 403
	o, e = c.Observe(context.Background(), "abcdefghijklmno", target, now, time.Minute)
	if e == nil || o.State != readmodel.SourceUnknown {
		t.Fatal("scope denial fabricated health", o, e)
	}
	before := calls
	if _, e = c.Observe(context.Background(), "../protected", target, now, time.Minute); e == nil || calls != before {
		t.Fatal("invalid target contacted provider")
	}
	code = 200
	body = `{"id":"wrong","status":"up","updated":"2026-10-28 11:59:59.000Z"}`
	if _, e = c.Observe(context.Background(), "abcdefghijklmno", target, now, time.Minute); e == nil {
		t.Fatal("identity mismatch accepted")
	}
}
