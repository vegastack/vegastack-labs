//go:build linux

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter/beszel"
	"github.com/vegastack/vegastack-labs/internal/adapter/githubalerts"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/operations"
)

// Continue the acknowledged G-011 fixture through ordinary server collection,
// SQLite alert/outbox persistence and concrete provider clients. Only provider
// HTTP and credential material are synthetic; this is not native or live proof.
func testOperationsFailureRecovery(t *testing.T, ctx context.Context, m *operationsMonitoring, exec func(string, ...any), advance func(time.Duration)) {
	t.Helper()
	const target = "synthetic-monitor"
	const record = "abcdefghijklmno"
	exec(`INSERT INTO read_principals VALUES('operator-a','active',1,'now','now')`)
	exec(`INSERT INTO read_grants VALUES('operator-a','platform.source.read','platform-source','database',1,'active','now','now')`)
	exec(`INSERT INTO read_grants VALUES('operator-a','operations.target.read','operations-target',?,1,'active','now','now')`, target)
	m.p.OperationsBeszel = []generated.OperationsBeszelBinding{{TargetID: target, RecordID: record, StaleAfterSeconds: 60}}

	status, sample := "down", m.clock().UTC()
	issueBody, issueState := "", ""
	creates, closes, requests, borrows := 0, 0, 0, 0
	deliveryDown := true
	transport := notificationWorkflowTransport(func(r *http.Request) (*http.Response, error) {
		requests++
		code := http.StatusOK
		var reply any
		switch r.URL.Host {
		case "monitor.example":
			if r.Method != http.MethodGet || r.URL.Path != "/api/collections/systems/records/"+record {
				t.Fatal("unexpected monitor request")
			}
			reply = map[string]any{"id": record, "status": status, "updated": sample.Format(time.RFC3339Nano), "name": "synthetic-private-host"}
		case "api.example":
			if deliveryDown {
				code, reply = http.StatusServiceUnavailable, map[string]any{"message": "synthetic-private-provider-error"}
				break
			}
			switch {
			case r.Method == http.MethodGet && r.URL.Path == "/repos/owner/alerts":
				reply = map[string]any{"id": 123, "full_name": "owner/alerts"}
			case r.Method == http.MethodGet && r.URL.Path == "/repos/owner/alerts/issues":
				reply = []any{}
				if issueBody != "" {
					reply = []any{map[string]any{"number": 21, "body": issueBody, "state": issueState}}
				}
			case r.Method == http.MethodPost && r.URL.Path == "/repos/owner/alerts/issues", r.Method == http.MethodPatch && r.URL.Path == "/repos/owner/alerts/issues/21":
				var body struct{ Body, State string }
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Fatal(err)
				}
				issueBody, issueState = body.Body, "open"
				if r.Method == http.MethodPost {
					creates++
				}
				if body.State == "closed" {
					issueState = "closed"
					closes++
				}
				reply = map[string]any{"number": 21, "state": issueState}
			default:
				t.Fatal("unexpected alert request", r.Method, r.URL.Path)
			}
		default:
			t.Fatal("request escaped synthetic providers")
		}
		raw, err := json.Marshal(reply)
		if err != nil {
			t.Fatal(err)
		}
		return &http.Response{StatusCode: code, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(string(raw)))}, nil
	})
	borrow := func(_ context.Context, purpose, digest string) (*credentialref.Value, error) {
		borrows++
		if !(purpose == "operations.beszel.read" && digest == operations.Digest(target) || purpose == "operations.github-issues.write" && digest == operations.Digest("owner/alerts")) {
			t.Fatal("unexpected credential scope")
		}
		return credentialref.NewValue([]byte("synthetic-credential-value"))
	}
	var err error
	m.beszel = map[string]*beszel.Client{}
	m.beszel[target], err = beszel.New("https://monitor.example", transport, borrow)
	if err != nil {
		t.Fatal(err)
	}
	m.github, err = githubalerts.New("https://api.example", "owner/alerts", 123, transport, borrow)
	if err != nil {
		t.Fatal(err)
	}
	command := operationsCLIWorkflow(t, ctx, m)
	// Route permission is checked before collection, even with valid source
	// and monitor grants. Grant it only after verifying this denial.
	if envelope, _, code := command("observe", false); code == 0 || len(envelope.Errors) != 1 || envelope.Errors[0].Code != generated.ErrorCodeAuthorizationDenied || requests != 0 || borrows != 0 {
		t.Fatal("API route authorization did not precede collection")
	}
	for _, capability := range []string{"operations.read", "operations.observe"} {
		exec(`INSERT INTO read_grants VALUES('operator-a',?,'operations-view','current',1,'active','now','now')`, capability)
	}
	observe := func() generated.OperationsStatusData {
		t.Helper()
		envelope, _, code := command("observe", false)
		if code != 0 {
			t.Fatal("manual observe command failed", envelope.Errors)
		}
		var got generated.OperationsStatusData
		if err := json.Unmarshal(envelope.Data, &got); err != nil {
			t.Fatal(err)
		}
		before, borrowed := requests, borrows
		read, _, code := command("status", false)
		if code != 0 || !bytes.Equal(read.Data, envelope.Data) {
			t.Fatal("manual status differs from collected state", read.Errors)
		}
		_, human, code := command("status", true)
		if code != 0 {
			t.Fatal("manual human status failed")
		}
		for _, alert := range got.Alerts {
			if !strings.Contains(human, alert.Key+" "+alert.ObservationState+" "+alert.Status) {
				t.Fatal("human status omitted machine alert state")
			}
		}
		if requests != before || borrows != borrowed {
			t.Fatal("manual status contacted a provider or borrowed credentials")
		}
		return got
	}
	assertAlert := func(got generated.OperationsStatusData, state, observation string, deliveries int) {
		t.Helper()
		found := 0
		for _, alert := range got.Alerts {
			if alert.TargetDigest == operations.Digest(target) {
				found++
				if alert.Status != state || alert.ObservationState != observation {
					t.Fatalf("alert status=%s observation=%s", alert.Status, alert.ObservationState)
				}
			}
		}
		if found != 1 || len(got.Deliveries) != deliveries {
			t.Fatalf("target alerts=%d deliveries=%d, wanted 1/%d", found, len(got.Deliveries), deliveries)
		}
		raw, err := json.Marshal(got)
		if err != nil {
			t.Fatal(err)
		}
		for _, private := range []string{"synthetic-private-host", "synthetic-private-provider-error", "synthetic-credential-value"} {
			if strings.Contains(string(raw)+issueBody, private) {
				t.Fatal("private provider material escaped")
			}
		}
	}
	assertAlert(observe(), "open", "failed", 1)
	advance(time.Second)
	assertAlert(observe(), "open", "failed", 1)
	m.dispatch(ctx)
	got, err := m.status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	assertAlert(got, "open", "failed", 1)
	if got.Deliveries[0].Status != string(audit.OutboxRetryWait) || got.Deliveries[0].AttemptCount != 1 || creates != 0 {
		t.Fatal("destination outage lost alert or retry", got.Deliveries)
	}
	deliveryDown = false
	before := requests
	m.dispatch(ctx)
	if requests != before {
		t.Fatal("retry ignored its due time")
	}
	advance(time.Minute)
	m.dispatch(ctx)
	if creates != 1 || issueState != "open" {
		t.Fatal("due retry did not deliver exactly one issue", creates, issueState)
	}
	// An up status with an old sample cannot close the incident.
	status = "up"
	assertAlert(observe(), "open", "stale", 1)
	m.dispatch(ctx)
	if closes != 0 {
		t.Fatal("stale sample closed external issue")
	}
	advance(time.Second)
	sample = m.clock().UTC()
	assertAlert(observe(), "closed", "healthy", 2)
	m.dispatch(ctx)
	m.dispatch(ctx)
	got, err = m.status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	assertAlert(got, "closed", "healthy", 2)
	if creates != 1 || closes != 1 || issueState != "closed" {
		t.Fatal("recovery duplicated or failed delivery", creates, closes, issueState)
	}
	for _, delivery := range got.Deliveries {
		if delivery.Status != string(audit.OutboxDelivered) {
			t.Fatal("delivery not persisted", delivery.Status)
		}
	}
	// A recipient revocation invalidates G-011. Even a new pending alert must
	// remain local instead of borrowing credentials or contacting the destination.
	exec(`UPDATE effective_authorization_principals SET status='revoked',grant_revision=2 WHERE principal_id='secondary-human'`)
	advance(time.Second)
	status, sample = "down", m.clock().UTC()
	assertAlert(observe(), "open", "failed", 3)
	before, borrowed := requests, borrows
	m.dispatch(ctx)
	if requests != before || borrows != borrowed {
		t.Fatal("revoked notification readiness contacted the destination")
	}
	// Revoke only the exact monitor read grant: authenticated collection must
	// fail before borrowing credentials or contacting any configured provider.
	exec(`UPDATE read_grants SET status='revoked' WHERE capability='operations.target.read' AND resource_id=?`, target)
	before, borrowed = requests, borrows
	if envelope, _, code := command("observe", false); code == 0 || len(envelope.Errors) != 1 || envelope.Errors[0].Code != generated.ErrorCodeAuthorizationDenied {
		t.Fatal("revoked target read allowed")
	}
	if _, err := m.observe(identity.WithVerifiedPrincipal(context.Background(), identity.Principal{ID: "ungranted", Method: identity.LocalOSPeerMethod})); err == nil {
		t.Fatal("ungranted principal allowed")
	}
	if requests != before || borrows != borrowed {
		t.Fatal("denied collection borrowed credentials or contacted a provider")
	}

}
