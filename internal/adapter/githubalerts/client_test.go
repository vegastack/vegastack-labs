package githubalerts

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/operations"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestIssueRetryDedupeUpdateAndVerifiedClose(t *testing.T) {
	ctx := context.Background()
	number := 0
	body := ""
	state := ""
	creates := 0
	failAfterCreate := true
	tr := transportFunc(func(r *http.Request) (*http.Response, error) {
		reply := any(map[string]any{})
		switch {
		case r.URL.Path == "/repos/owner/alerts":
			reply = map[string]any{"id": 123, "full_name": "owner/alerts"}
		case r.Method == "GET":
			issues := []any{}
			if number > 0 {
				issues = append(issues, map[string]any{"number": number, "body": body})
			}
			reply = issues
		case r.Method == "POST" || r.Method == "PATCH":
			raw, _ := io.ReadAll(r.Body)
			if strings.Contains(string(raw), "seed-token") || strings.Contains(string(raw), "private-host") {
				t.Fatal("private value leaked")
			}
			var v map[string]any
			json.Unmarshal(raw, &v)
			body, _ = v["body"].(string)
			state = "open"
			if v["state"] == "closed" {
				state = "closed"
			}
			if r.Method == "POST" {
				creates++
				number = 17
			}
			reply = map[string]any{"number": number, "state": state}
			if failAfterCreate {
				failAfterCreate = false
				return nil, errors.New("uncertain response containing private-secret")
			}
		}
		raw, _ := json.Marshal(reply)
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(string(raw)))}, nil
	})
	c, e := New("https://api.example", "owner/alerts", 123, tr, func(_ context.Context, p, target string) (*credentialref.Value, error) {
		if p != "operations.github-issues.write" || target != operations.Digest("owner/alerts") {
			t.Fatal("scope")
		}
		return credentialref.NewValue([]byte("seed-token"))
	})
	if e != nil {
		t.Fatal(e)
	}
	event := audit.Event{Schema: audit.EventSchema, SchemaVersion: audit.EventSchemaVersion, EventID: 1, OccurredAt: time.Now().UTC().Format(time.RFC3339Nano), Type: "operations.alert.opened", CorrelationID: "operations-" + strings.Repeat("a", 32), PrincipalID: "operator-a", PrincipalMethod: "local-os-peer", Target: audit.Target{Kind: "operations-target", ID: operations.Digest("private-host")}}
	if e = c.Deliver(ctx, event); e != ErrUnavailable {
		t.Fatal("raw error exposed", e)
	}
	if e = c.Deliver(ctx, event); e != nil || creates != 1 || state != "open" {
		t.Fatal(creates, state, e)
	}
	event.Type = "operations.alert.closed"
	event.EventID = 2
	if e = c.Deliver(ctx, event); e != nil || creates != 1 || state != "closed" {
		t.Fatal(creates, state, e)
	}
	event.Type = "unreviewed.mutation"
	if e = c.Deliver(ctx, event); e == nil {
		t.Fatal("wrong event accepted")
	}
	wrong, _ := New("https://api.example", "owner/alerts", 999, tr, c.borrow)
	event.Type = "operations.alert.opened"
	if e = wrong.Deliver(ctx, event); e == nil {
		t.Fatal("repository mismatch accepted")
	}
}
