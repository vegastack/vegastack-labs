// Package slack implements the typed Slack Socket Mode boundary for human
// acknowledgement. It emits only provider-neutral candidates.
package slack

import (
	"context"
	"time"

	"github.com/vegastack/vegastack-labs/internal/acknowledgement"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

const (
	MaxEnvelopeBytes = 64 << 10
	MaxJSONDepth     = 16
	credentialUse    = "slack-acknowledgement"
)

type Config struct {
	AppTokenReference credentialref.Reference
	BotTokenReference credentialref.Reference
	WorkspaceID       string
	SlackUserID       string
	HumanID           string
	AuthorityID       string
	ChannelID         string
	ApproveActionID   string
	RejectActionID    string
	ReconnectDelay    time.Duration
	MaxReconnectDelay time.Duration
}

type CredentialResolver interface {
	Resolve(context.Context, credentialref.Reference) ([]byte, error)
}

type Socket interface {
	Receive(context.Context) ([]byte, error)
	Acknowledge(context.Context, string) error
	Close() error
}

type Transport interface {
	Open(context.Context, []byte) (Socket, error)
	Publish(context.Context, []byte, string, string, string, acknowledgement.RequestCard) error
}

type CandidateSink interface {
	Submit(context.Context, acknowledgement.Candidate) error
}

type CandidateSinkFunc func(context.Context, acknowledgement.Candidate) error

func (function CandidateSinkFunc) Submit(ctx context.Context, candidate acknowledgement.Candidate) error {
	return function(ctx, candidate)
}

type Logger interface{ Event(string) }

type Adapter struct {
	config    Config
	resolver  CredentialResolver
	transport Transport
	sink      CandidateSink
	clock     func() time.Time
	logger    Logger
}

func NewAdapter(config Config, resolver CredentialResolver, transport Transport, sink CandidateSink) (*Adapter, error) {
	if !validConfig(config) || resolver == nil || transport == nil || sink == nil {
		return nil, slackError(generated.ErrorCodeInputInvalid, "slack-adapter", false)
	}
	if config.MaxReconnectDelay == 0 {
		config.MaxReconnectDelay = 5 * time.Second
	}
	return &Adapter{config: config, resolver: resolver, transport: transport, sink: sink, clock: time.Now}, nil
}

func (adapter *Adapter) Publish(ctx context.Context, card acknowledgement.RequestCard) error {
	if adapter == nil || ctx == nil || card.Nonce == "" || card.Request.PlanID == "" {
		return slackError(generated.ErrorCodeInputInvalid, "slack-request-card", false)
	}
	token, err := adapter.resolve(ctx, adapter.config.BotTokenReference)
	if err != nil {
		return err
	}
	defer zero(token)
	if err := adapter.transport.Publish(ctx, token, adapter.config.ChannelID, adapter.config.ApproveActionID, adapter.config.RejectActionID, card); err != nil {
		adapter.log("publish-unavailable")
		return slackError(generated.ErrorCodeDependencyUnavailable, "slack-publish", true)
	}
	adapter.log("request-published")
	return nil
}

func (adapter *Adapter) Run(ctx context.Context) error {
	if adapter == nil || ctx == nil {
		return slackError(generated.ErrorCodeInputInvalid, "slack-adapter", false)
	}
	delay := adapter.config.ReconnectDelay
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		token, err := adapter.resolve(ctx, adapter.config.AppTokenReference)
		if err != nil {
			return err
		}
		socket, openErr := adapter.transport.Open(ctx, token)
		zero(token)
		if openErr != nil {
			adapter.log("connection-unavailable")
			if err := waitReconnect(ctx, delay); err != nil {
				return err
			}
			delay = nextDelay(delay, adapter.config.MaxReconnectDelay)
			continue
		}
		delay = adapter.config.ReconnectDelay
		adapter.log("connected")
		reconnect, runErr := adapter.consume(ctx, socket)
		_ = socket.Close()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if runErr != nil {
			adapter.log("connection-interrupted")
		}
		if !reconnect && runErr == nil {
			return nil
		}
		if err := waitReconnect(ctx, delay); err != nil {
			return err
		}
		delay = nextDelay(delay, adapter.config.MaxReconnectDelay)
	}
}

func (adapter *Adapter) consume(ctx context.Context, socket Socket) (bool, error) {
	for {
		raw, err := socket.Receive(ctx)
		if err != nil {
			return true, err
		}
		header, err := decodeHeader(ctx, raw)
		if err != nil {
			adapter.log("envelope-rejected")
			continue
		}
		if header.EnvelopeID != "" {
			if err := socket.Acknowledge(ctx, header.EnvelopeID); err != nil {
				return true, err
			}
		}
		switch header.Type {
		case "hello", "events_api":
			continue
		case "disconnect":
			adapter.log("refresh-requested")
			return true, nil
		case "interactive":
			candidate, err := decodeCandidate(ctx, adapter.config, raw, adapter.clock().UTC().Truncate(time.Second))
			if err != nil {
				adapter.log("action-rejected")
				continue
			}
			if err := adapter.sink.Submit(ctx, candidate); err != nil {
				adapter.log("decision-rejected")
			}
		default:
			adapter.log("envelope-ignored")
		}
	}
}

func (adapter *Adapter) resolve(ctx context.Context, reference credentialref.Reference) ([]byte, error) {
	if reference.Consumer != credentialUse {
		return nil, slackError(generated.ErrorCodeAuthorizationDenied, "slack-credential", false)
	}
	value, err := adapter.resolver.Resolve(ctx, reference)
	if err != nil || !validToken(value) {
		zero(value)
		return nil, slackError(generated.ErrorCodeDependencyUnavailable, "slack-credential", true)
	}
	return append([]byte(nil), value...), nil
}

func (adapter *Adapter) log(event string) {
	if adapter.logger != nil {
		adapter.logger.Event(event)
	}
}

func validConfig(config Config) bool {
	for _, value := range []string{config.AppTokenReference.ID, config.BotTokenReference.ID, config.WorkspaceID, config.SlackUserID, config.HumanID, config.AuthorityID, config.ChannelID, config.ApproveActionID, config.RejectActionID} {
		if !authorization.ValidIdentifier(value) {
			return false
		}
	}
	return config.AppTokenReference.Consumer == credentialUse && config.BotTokenReference.Consumer == credentialUse && config.AppTokenReference.ID != config.BotTokenReference.ID && config.ApproveActionID != config.RejectActionID && config.ReconnectDelay > 0 && config.ReconnectDelay <= 5*time.Second && (config.MaxReconnectDelay == 0 || (config.MaxReconnectDelay >= config.ReconnectDelay && config.MaxReconnectDelay <= time.Minute))
}

func validToken(value []byte) bool {
	return len(value) >= 8 && len(value) <= 4096
}

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func waitReconnect(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func nextDelay(current, maximum time.Duration) time.Duration {
	if current >= maximum/2 {
		return maximum
	}
	return current * 2
}

func slackError(code, target string, retryable bool) error {
	return failure.New(code, target, retryable)
}
