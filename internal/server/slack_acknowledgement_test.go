package server

import (
	"context"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/acknowledgement"
	"github.com/vegastack/vegastack-labs/internal/adapters/slack"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/localapi"
)

func TestSlackAcknowledgementConnectionIsServerOwnedAndStopsWithServer(t *testing.T) {
	listener := newTestListener(t, true)
	transport := &serverSlackTransport{started: make(chan struct{}), stopped: make(chan struct{})}
	adapter, err := slack.NewAdapter(slack.Config{
		AppTokenReference: credentialref.Reference{ID: "slack-app-token", Consumer: "slack-acknowledgement"},
		BotTokenReference: credentialref.Reference{ID: "slack-bot-token", Consumer: "slack-acknowledgement"},
		WorkspaceID:       "workspace-approved", SlackUserID: "user-approved", HumanID: "person-operator", AuthorityID: "authority-slack",
		ChannelID: "channel-approval", ApproveActionID: "action-approve", RejectActionID: "action-reject", ReconnectDelay: time.Millisecond,
	}, serverSlackResolver{}, transport, slack.CandidateSinkFunc(func(context.Context, acknowledgement.Candidate) error { return nil }))
	if err != nil {
		t.Fatal(err)
	}
	service, err := New(Config{
		Profile:           testServerProfile(),
		Application:       &testApplication{},
		Results:           testResultFactory(),
		ListenerFactory:   func(context.Context, localapi.ListenConfig) (localapi.Listener, error) { return listener, nil },
		PlatformProbe:     staticPlatformProbe{platform: testSupportedPlatform()},
		IntegrityInterval: time.Hour,
		Background:        adapter,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- service.Run(ctx) }()
	select {
	case <-transport.started:
	case <-time.After(time.Second):
		t.Fatal("server did not start acknowledgement connection")
	}
	cancel()
	select {
	case <-transport.stopped:
	case <-time.After(time.Second):
		t.Fatal("server did not stop acknowledgement connection")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not stop")
	}
	if transport.calls != 1 {
		t.Fatalf("connections = %d", transport.calls)
	}
}

type serverSlackResolver struct{}

func (serverSlackResolver) Resolve(context.Context, credentialref.Reference) ([]byte, error) {
	return []byte("xapp-fixture-secret"), nil
}

type serverSlackTransport struct {
	started chan struct{}
	stopped chan struct{}
	calls   int
}

func (transport *serverSlackTransport) Open(context.Context, []byte) (slack.Socket, error) {
	transport.calls++
	close(transport.started)
	return &serverSlackSocket{stopped: transport.stopped}, nil
}

func (*serverSlackTransport) Publish(context.Context, []byte, string, string, string, acknowledgement.RequestCard) error {
	return nil
}

type serverSlackSocket struct{ stopped chan struct{} }

func (socket *serverSlackSocket) Receive(ctx context.Context) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}
func (*serverSlackSocket) Acknowledge(context.Context, string) error { return nil }
func (socket *serverSlackSocket) Close() error {
	close(socket.stopped)
	return nil
}
