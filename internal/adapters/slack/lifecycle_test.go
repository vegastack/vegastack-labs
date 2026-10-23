package slack

import (
	"context"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/acknowledgement"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestApprovalCardLifecycleRemovesButtons(t *testing.T) {
	transport, payload, calls := lifecycleTransport(t)
	card := reviewTextCard("Exact requested change")
	if err := transport.Publish(context.Background(), []byte(fixtureSlackCredential), "channel-approval", "action-approve", "action-reject", card); err != nil {
		t.Fatal(err)
	}
	updater, ok := any(transport).(interface {
		Refresh(context.Context, []byte, func(context.Context, string, string) (string, error)) error
	})
	if !ok {
		t.Fatal("published approval card has no automatic lifecycle update path")
	}
	for _, state := range []string{"approved", "succeeded"} {
		if err := updater.Refresh(context.Background(), []byte(fixtureSlackCredential), func(context.Context, string, string) (string, error) { return state, nil }); err != nil {
			t.Fatal(err)
		}
		var msg struct {
			Blocks []any  `json:"blocks"`
			Text   string `json:"text"`
			TS     string `json:"ts"`
		}
		if err := json.Unmarshal(*payload, &msg); err != nil {
			t.Fatal(err)
		}
		if len(msg.Blocks) != 0 || msg.TS != "123.456" || !strings.Contains(msg.Text, "Exact requested change") {
			t.Fatalf("card not replaced: %s", *payload)
		}
	}
	if *calls != 3 {
		t.Fatalf("calls=%d", *calls)
	}
}

func lifecycleTransport(t *testing.T) (*HTTPTransport, *[]byte, *int) {
	t.Helper()
	var payload []byte
	calls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/chat" && r.URL.Path != "/api/chat.update" {
			t.Errorf("wrong endpoint %s", r.URL.Path)
		}
		payload, _ = io.ReadAll(r.Body)
		_, _ = w.Write([]byte(`{"ok":true,"channel":"channel-approval","ts":"123.456"}`))
	}))
	t.Cleanup(server.Close)
	client := server.Client()
	client.Timeout = time.Second
	client.Transport = &slackFixtureRoundTripper{base: client.Transport, origin: server.URL}
	transport, err := NewHTTPTransport(client)
	if err != nil {
		t.Fatal(err)
	}
	return transport, &payload, &calls
}

func TestApprovalCardTerminalStates(t *testing.T) {
	for _, state := range []string{"rejected", "expired", "stale", "failed", "partial", "cancelled"} {
		t.Run(state, func(t *testing.T) {
			transport, payload, calls := lifecycleTransport(t)
			if err := transport.Publish(context.Background(), []byte(fixtureSlackCredential), "channel-approval", "approve", "reject", reviewTextCard("Exact scope")); err != nil {
				t.Fatal(err)
			}
			read := func(context.Context, string, string) (string, error) { return state, nil }
			if err := transport.Refresh(context.Background(), []byte(fixtureSlackCredential), read); err != nil {
				t.Fatal(err)
			}
			var msg struct {
				Blocks []any  `json:"blocks"`
				Text   string `json:"text"`
			}
			if err := json.Unmarshal(*payload, &msg); err != nil {
				t.Fatal(err)
			}
			if len(msg.Blocks) != 0 || strings.Contains(msg.Text, "APPLIED") {
				t.Fatalf("incorrect terminal status: %s", *payload)
			}
			if err := transport.Refresh(context.Background(), []byte(fixtureSlackCredential), read); err != nil {
				t.Fatal(err)
			}
			if *calls != 2 {
				t.Fatalf("repeated terminal update calls=%d", *calls)
			}
		})
	}
}

type receiptMemory struct {
	rows []acknowledgement.MessageReceipt
}

func (r *receiptMemory) SaveMessageReceipt(_ context.Context, m acknowledgement.MessageReceipt) error {
	r.rows = append(r.rows, m)
	return nil
}
func (r *receiptMemory) MessageReceipts(context.Context) ([]acknowledgement.MessageReceipt, error) {
	return r.rows, nil
}
func (r *receiptMemory) CompleteMessageReceipt(_ context.Context, dest, id, state string) error {
	for i := range r.rows {
		if r.rows[i].Destination == dest && r.rows[i].MessageID == id {
			r.rows[i].Status = state
		}
	}
	return nil
}
func TestCardUpdatesResumeFromStoredReceipt(t *testing.T) {
	repo := &receiptMemory{}
	first, _, _ := lifecycleTransport(t)
	first.SetReceiptRepository(repo, "channel-approval")
	if err := first.Publish(context.Background(), []byte(fixtureSlackCredential), "channel-approval", "approve", "reject", reviewTextCard("Persisted scope")); err != nil {
		t.Fatal(err)
	}
	second, payload, calls := lifecycleTransport(t)
	second.SetReceiptRepository(repo, "channel-approval")
	if err := second.Refresh(context.Background(), []byte(fixtureSlackCredential), func(context.Context, string, string) (string, error) { return "succeeded", nil }); err != nil {
		t.Fatal(err)
	}
	if *calls != 1 || !strings.Contains(string(*payload), "APPLIED") || repo.rows[0].Status != "succeeded" {
		t.Fatalf("restart update missing: %s", *payload)
	}
}

func TestCardUpdateHonorsSlackRetryAfter(t *testing.T) {
	calls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()
	client := server.Client()
	client.Timeout = time.Second
	client.Transport = &slackFixtureRoundTripper{base: client.Transport, origin: server.URL}
	transport, err := NewHTTPTransport(client)
	if err != nil {
		t.Fatal(err)
	}
	transport.messages["receipt"] = messageReceipt{Channel: "channel-approval", TS: "123.456", PlanID: "plan", Digest: "digest"}
	read := func(context.Context, string, string) (string, error) { return "approved", nil }
	if err := transport.Refresh(context.Background(), []byte(fixtureSlackCredential), read); err == nil {
		t.Fatal("rate limit not reported")
	}
	if err := transport.Refresh(context.Background(), []byte(fixtureSlackCredential), read); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || len(transport.messages) != 1 {
		t.Fatalf("retried before Retry-After or lost receipt: calls=%d", calls)
	}
}

func TestInterruptedCardFollowsResumedRun(t *testing.T) {
	transport, payload, _ := lifecycleTransport(t)
	transport.messages["receipt"] = messageReceipt{Channel: "channel-approval", TS: "123.456", PlanID: "plan", Digest: "digest"}
	for _, state := range []string{"interrupted", "running", "succeeded"} {
		if err := transport.Refresh(context.Background(), []byte(fixtureSlackCredential), func(context.Context, string, string) (string, error) { return state, nil }); err != nil {
			t.Fatal(err)
		}
	}
	if !strings.Contains(string(*payload), "APPLIED") {
		t.Fatalf("resumed card not updated: %s", *payload)
	}
}

type lifecycleRunTransport struct {
	fixtureTransport
	refreshed chan string
}

func (t *lifecycleRunTransport) Refresh(ctx context.Context, _ []byte, read func(context.Context, string, string) (string, error)) error {
	state, err := read(ctx, "plan", "digest")
	if err == nil {
		select {
		case t.refreshed <- state:
		default:
		}
	}
	return err
}

type lifecycleRunSink struct{ CandidateSinkFuncs }

func (lifecycleRunSink) MessageStatus(context.Context, string, string) (string, error) {
	return "approved", nil
}
func TestAdapterRunAutomaticallyRefreshesCards(t *testing.T) {
	transport := &lifecycleRunTransport{refreshed: make(chan string, 1)}
	adapter, err := NewAdapter(testConfig(), fixtureResolver{}, transport, lifecycleRunSink{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- adapter.Run(ctx) }()
	select {
	case state := <-transport.refreshed:
		if state != "approved" {
			t.Fatal(state)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("background updater did not run")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("updater did not stop")
	}
}
