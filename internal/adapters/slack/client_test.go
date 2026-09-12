package slack

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/vegastack/vegastack-labs/internal/acknowledgement"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

const fixtureSlackCredential = "x" + "app-fixture-secret"

const slackTestDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestSocketModeAcknowledgesEnvelopeAndReconnectsWithoutLeakingURL(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	transport := &fixtureTransport{sessions: [][]string{
		{`{"type":"hello"}`, `{"envelope_id":"env-1","type":"events_api","payload":{"type":"app_mention"}}`, `{"type":"disconnect","reason":"refresh_requested"}`},
		{`{"type":"hello"}`, fixtureInteractive("env-2", "workspace-approved", "user-approved", "action-approve")},
	}}
	var candidates []acknowledgement.Candidate
	adapter, err := NewAdapter(testConfig(), fixtureResolver{}, transport, testCandidateSink(func(_ context.Context, candidate acknowledgement.Candidate) error {
		candidates = append(candidates, candidate)
		cancel()
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	err = adapter.Run(ctx)
	if err != nil && !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if got := strings.Join(transport.acknowledged, ","); got != "env-1,env-2" {
		t.Fatalf("acknowledged = %q", got)
	}
	if transport.opened != 2 || len(candidates) != 1 || candidates[0].Action != acknowledgement.ActionApprove {
		t.Fatalf("opens/candidates = %d, %#v", transport.opened, candidates)
	}
	if strings.Contains(strings.Join(transport.logs, " "), "wss://") || strings.Contains(strings.Join(transport.logs, " "), "xapp-") {
		t.Fatalf("sensitive diagnostics = %q", transport.logs)
	}
}

func TestDecodeInteractiveRejectsWrongBindingMalformedAndOversized(t *testing.T) {
	config := testConfig()
	if _, err := decodeCandidate(context.Background(), config, []byte(fixtureInteractive("env-valid", "workspace-approved", "user-approved", "action-approve")), time.Date(2026, 9, 13, 1, 5, 0, 0, time.UTC)); err != nil {
		t.Fatalf("valid candidate: %v", err)
	}
	cases := []string{
		fixtureInteractive("env-1", "workspace-wrong", "user-approved", "action-approve"),
		fixtureInteractive("env-1", "workspace-approved", "user-wrong", "action-approve"),
		fixtureInteractive("env-1", "workspace-approved", "user-approved", "action-widen"),
		`{"envelope_id":"env-1","envelope_id":"env-2","type":"interactive"}`,
		strings.Repeat("x", MaxEnvelopeBytes+1),
	}
	for index, raw := range cases {
		if _, err := decodeCandidate(context.Background(), config, []byte(raw), time.Date(2026, 9, 13, 1, 5, 0, 0, time.UTC)); err == nil {
			t.Fatalf("case %d accepted", index)
		}
	}
}

func TestSocketModeCoversRejectDuplicateDisconnectAndTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	duplicate := fixtureInteractive("env-duplicate", "workspace-approved", "user-approved", "action-approve")
	transport := &fixtureTransport{sessions: [][]string{
		{duplicate, duplicate, `{"type":"disconnect","reason":"warning"}`},
		{fixtureInteractive("env-reject", "workspace-approved", "user-approved", "action-reject")},
	}}
	var candidates []acknowledgement.Candidate
	adapter, err := NewAdapter(testConfig(), fixtureResolver{}, transport, testCandidateSink(func(_ context.Context, candidate acknowledgement.Candidate) error {
		candidates = append(candidates, candidate)
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	err = adapter.Run(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("run error = %v", err)
	}
	if got := strings.Join(transport.acknowledged, ","); got != "env-duplicate,env-duplicate,env-reject" {
		t.Fatalf("acknowledged = %q", got)
	}
	if len(candidates) != 3 || candidates[0].Action != acknowledgement.ActionApprove || candidates[1].Action != acknowledgement.ActionApprove || candidates[2].Action != acknowledgement.ActionReject {
		t.Fatalf("candidates = %#v", candidates)
	}
}

func TestInteractiveEnvelopeAcknowledgesOnlyAfterDurableDecision(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	interactive := fixtureInteractive("env-retry", "workspace-approved", "user-approved", "action-reject")
	transport := &fixtureTransport{sessions: [][]string{{interactive}, {interactive}}}
	sink := &retryingCandidateSink{}
	adapter, err := NewAdapter(testConfig(), fixtureResolver{}, transport, sink)
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.Run(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("run = %v", err)
	}
	if sink.submits != 2 || strings.Join(transport.acknowledged, ",") != "env-retry" {
		t.Fatalf("submits/acks = %d/%v", sink.submits, transport.acknowledged)
	}
}

func TestRejectedAdapterActionIsAuditedBeforeEnvelopeAcknowledgement(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	transport := &fixtureTransport{sessions: [][]string{{fixtureInteractive("env-wrong", "workspace-wrong", "user-approved", "action-reject"), `{broken`}}}
	sink := &retryingCandidateSink{}
	adapter, err := NewAdapter(testConfig(), fixtureResolver{}, transport, sink)
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.Run(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("run = %v", err)
	}
	if sink.rejections != 2 || strings.Join(transport.acknowledged, ",") != "env-wrong" {
		t.Fatalf("rejections/acks = %d/%v", sink.rejections, transport.acknowledged)
	}
}

func TestHTTPTransportRefusesRedirects(t *testing.T) {
	redirected := false
	target := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		redirected = true
	}))
	defer target.Close()
	source := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, target.URL, http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	client := source.Client()
	client.Timeout = time.Second
	client.Transport = &slackFixtureRoundTripper{base: client.Transport, origin: source.URL}
	transport, err := NewHTTPTransport(client)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := transport.Open(context.Background(), []byte(fixtureSlackCredential)); err == nil {
		t.Fatal("redirect accepted")
	}
	if redirected {
		t.Fatal("authorization-bearing request followed redirect")
	}
}

func TestSocketURLAcceptsDocumentedTicketAndRejectsWidenedAuthority(t *testing.T) {
	transport := &HTTPTransport{}
	for _, raw := range []string{
		"wss://wss.slack.com/link/?ticket=1234-5678",
		"wss://wss-primary.slack.com/link/?ticket=12348&app_id=5678",
		"wss://wss-123.slack.com/link/?ticket=12348&app_id=5678",
	} {
		if !transport.allowedSocketURL(raw) {
			t.Fatalf("documented Slack URL rejected: %s", raw)
		}
	}
	for _, raw := range []string{
		"wss://evil.example/link/?ticket=12348",
		"wss://wss.slack.com.evil.example/link/?ticket=12348",
		"wss://wss.slack.com:443/link/?ticket=12348",
		"wss://wss.slack.com/other/?ticket=12348",
		"wss://wss.slack.com/link/",
		"wss://wss.slack.com/link/?ticket=one&ticket=two",
		"wss://wss.slack.com/link/?ticket=one&redirect=evil",
		"wss://user@wss.slack.com/link/?ticket=12348",
	} {
		if transport.allowedSocketURL(raw) {
			t.Fatalf("widened Slack URL accepted: %s", raw)
		}
	}
}

func TestAdapterCategorizesOutageAndDoesNotExposeCredential(t *testing.T) {
	transport := &fixtureTransport{openErr: errors.New("fixture outage")}
	adapter, err := NewAdapter(testConfig(), fixtureResolver{}, transport, testCandidateSink(func(context.Context, acknowledgement.Candidate) error { return nil }))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	err = adapter.Run(ctx)
	if err == nil || strings.Contains(err.Error(), fixtureSlackCredential) {
		t.Fatalf("outage error = %v", err)
	}
}

func TestHTTPAndWebSocketFixtureComposePublishAckAndCandidate(t *testing.T) {
	acknowledged := make(chan string, 1)
	var server *httptest.Server
	handler := http.NewServeMux()
	handler.HandleFunc("/open", func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+fixtureSlackCredential {
			http.Error(writer, "denied", http.StatusUnauthorized)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"ok":true,"url":"wss://wss.slack.com/link/?ticket=fixture-ticket&app_id=fixture-app"}`))
	})
	handler.HandleFunc("/chat", func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+fixtureSlackCredential {
			http.Error(writer, "denied", http.StatusUnauthorized)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"ok":true}`))
	})
	handler.HandleFunc("/socket", func(writer http.ResponseWriter, request *http.Request) {
		connection, err := websocket.Accept(writer, request, nil)
		if err != nil {
			return
		}
		defer connection.CloseNow()
		_ = connection.Write(request.Context(), websocket.MessageText, []byte(`{"type":"hello"}`))
		_ = connection.Write(request.Context(), websocket.MessageText, []byte(fixtureInteractive("env-local", "workspace-approved", "user-approved", "action-approve")))
		_, payload, err := connection.Read(request.Context())
		if err == nil {
			acknowledged <- string(payload)
		}
	})
	server = httptest.NewTLSServer(handler)
	defer server.Close()
	client := server.Client()
	client.Timeout = 2 * time.Second
	client.Transport = &slackFixtureRoundTripper{base: client.Transport, origin: server.URL}
	transport, err := NewHTTPTransport(client)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	candidateReceived := make(chan struct{}, 1)
	adapter, err := NewAdapter(testConfig(), fixtureResolver{}, transport, testCandidateSink(func(context.Context, acknowledgement.Candidate) error {
		candidateReceived <- struct{}{}
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	adapter.clock = func() time.Time { return time.Date(2026, 9, 13, 1, 5, 0, 0, time.UTC) }
	request := generated.AcknowledgementRequest{Schema: generated.SchemaIDAcknowledgementRequest, SchemaVersion: "1.0.0", PlanID: "plan-test", PlanDigest: slackTestDigest, TargetDigest: slackTestDigest, ReasonDigest: slackTestDigest, HumanID: "person-operator", AuthorityID: "authority-slack", NonceDigest: slackTestDigest, StateRevision: 41, RecoveryEpoch: 3, ExpiresAt: "2026-09-13T01:30:00Z", Extensions: []generated.ContractExtension{}}
	if err := adapter.Publish(context.Background(), acknowledgement.RequestCard{Request: request, AcknowledgementID: "ack-test", Nonce: "nonce-one-time"}); err != nil {
		t.Fatal(err)
	}
	runDone := make(chan error, 1)
	go func() { runDone <- adapter.Run(ctx) }()
	select {
	case payload := <-acknowledged:
		if payload != `{"envelope_id":"env-local"}` {
			t.Fatalf("ack = %s", payload)
		}
	case <-time.After(time.Second):
		t.Fatal("fixture did not receive envelope acknowledgement")
	}
	select {
	case <-candidateReceived:
	case <-time.After(time.Second):
		t.Fatal("fixture candidate was not submitted")
	}
	cancel()
	if err := <-runDone; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func testConfig() Config {
	return Config{
		AppTokenReference: credentialref.Reference{ID: "slack-app-token", Consumer: "slack-acknowledgement"},
		BotTokenReference: credentialref.Reference{ID: "slack-bot-token", Consumer: "slack-acknowledgement"},
		WorkspaceID:       "workspace-approved", SlackUserID: "user-approved", HumanID: "person-operator", AuthorityID: "authority-slack",
		ChannelID: "channel-approval", ApproveActionID: "action-approve", RejectActionID: "action-reject",
		ReconnectDelay: time.Millisecond,
	}
}

type fixtureResolver struct{}

func (fixtureResolver) Resolve(context.Context, credentialref.Reference) ([]byte, error) {
	return []byte(fixtureSlackCredential), nil
}

type retryingCandidateSink struct {
	submits    int
	rejections int
}

func (sink *retryingCandidateSink) Submit(context.Context, acknowledgement.Candidate) error {
	sink.submits++
	if sink.submits == 1 {
		return errors.New("fixture durable store unavailable")
	}
	return nil
}

func (sink *retryingCandidateSink) Reject(context.Context, acknowledgement.AdapterRejection) error {
	sink.rejections++
	return nil
}

type fixtureTransport struct {
	mu           sync.Mutex
	sessions     [][]string
	opened       int
	acknowledged []string
	logs         []string
	openErr      error
}

func (transport *fixtureTransport) Open(context.Context, []byte) (Socket, error) {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if transport.openErr != nil {
		return nil, transport.openErr
	}
	if transport.opened >= len(transport.sessions) {
		return &fixtureSocket{transport: transport}, nil
	}
	messages := transport.sessions[transport.opened]
	transport.opened++
	return &fixtureSocket{transport: transport, messages: messages}, nil
}

func (transport *fixtureTransport) Publish(context.Context, []byte, string, string, string, acknowledgement.RequestCard) error {
	return nil
}

type fixtureSocket struct {
	transport *fixtureTransport
	messages  []string
	index     int
}

func (socket *fixtureSocket) Receive(ctx context.Context) ([]byte, error) {
	if socket.index >= len(socket.messages) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	value := []byte(socket.messages[socket.index])
	socket.index++
	return value, nil
}

func (socket *fixtureSocket) Acknowledge(_ context.Context, envelopeID string) error {
	socket.transport.mu.Lock()
	defer socket.transport.mu.Unlock()
	socket.transport.acknowledged = append(socket.transport.acknowledged, envelopeID)
	return nil
}

func (*fixtureSocket) Close() error { return nil }

func fixtureInteractive(envelopeID, workspaceID, userID, actionID string) string {
	binding, _ := json.Marshal(actionBinding{PlanID: "plan-test", PlanDigest: slackTestDigest, TargetDigest: slackTestDigest, ReasonDigest: slackTestDigest, Nonce: "nonce-one-time", StateRevision: 41, RecoveryEpoch: 3, ExpiresAt: "2026-09-13T01:30:00Z"})
	envelope := map[string]any{"envelope_id": envelopeID, "type": "interactive", "payload": map[string]any{"type": "block_actions", "team": map[string]string{"id": workspaceID}, "user": map[string]string{"id": userID}, "actions": []any{map[string]string{"action_id": actionID, "value": string(binding)}}}}
	raw, _ := json.Marshal(envelope)
	return string(raw)
}

func testCandidateSink(submit func(context.Context, acknowledgement.Candidate) error) CandidateSinkFuncs {
	return CandidateSinkFuncs{SubmitFunc: submit, RejectFunc: func(context.Context, acknowledgement.AdapterRejection) error { return nil }}
}

type slackFixtureRoundTripper struct {
	base   http.RoundTripper
	origin string
}

func (transport *slackFixtureRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	origin, err := url.Parse(transport.origin)
	if err != nil {
		return nil, err
	}
	copyRequest := request.Clone(request.Context())
	copyURL := *request.URL
	copyRequest.URL = &copyURL
	copyRequest.URL.Scheme = origin.Scheme
	copyRequest.URL.Host = origin.Host
	switch request.URL.Hostname() {
	case "slack.com":
		switch request.URL.Path {
		case "/api/apps.connections.open":
			copyRequest.URL.Path = "/open"
		case "/api/chat.postMessage":
			copyRequest.URL.Path = "/chat"
		}
	case "wss.slack.com":
		copyRequest.URL.Path = "/socket"
		copyRequest.URL.RawQuery = ""
	}
	return transport.base.RoundTrip(copyRequest)
}
