// Package slack implements the typed Slack Socket Mode boundary for human
// acknowledgement. It emits only provider-neutral candidates.
package slack

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/vegastack/vegastack-labs/internal/acknowledgement"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/strictjson"
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
	Reject(context.Context, acknowledgement.AdapterRejection) error
}

type CandidateSinkFuncs struct {
	SubmitFunc func(context.Context, acknowledgement.Candidate) error
	RejectFunc func(context.Context, acknowledgement.AdapterRejection) error
}

func (sink CandidateSinkFuncs) Submit(ctx context.Context, candidate acknowledgement.Candidate) error {
	return sink.SubmitFunc(ctx, candidate)
}

func (sink CandidateSinkFuncs) Reject(ctx context.Context, rejection acknowledgement.AdapterRejection) error {
	return sink.RejectFunc(ctx, rejection)
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
			if rejectErr := adapter.recordRejection(ctx, raw, generated.ErrorCodeInputInvalid); rejectErr != nil {
				adapter.log("rejection-audit-unavailable")
				return true, rejectErr
			}
			adapter.log("envelope-rejected")
			continue
		}
		switch header.Type {
		case "hello", "events_api":
			if err := acknowledgeEnvelope(ctx, socket, header.EnvelopeID); err != nil {
				return true, err
			}
			continue
		case "disconnect":
			if err := acknowledgeEnvelope(ctx, socket, header.EnvelopeID); err != nil {
				return true, err
			}
			adapter.log("refresh-requested")
			return true, nil
		case "interactive":
			candidate, err := decodeCandidate(ctx, adapter.config, raw, adapter.clock().UTC().Truncate(time.Second))
			if err != nil {
				reason := generated.ErrorCodeAuthorizationDenied
				if stable, ok := failure.As(err); ok && stable.Code == generated.ErrorCodeInputInvalid {
					reason = generated.ErrorCodeInputInvalid
				}
				if rejectErr := adapter.recordRejection(ctx, raw, reason); rejectErr != nil {
					adapter.log("rejection-audit-unavailable")
					return true, rejectErr
				}
				if err := acknowledgeEnvelope(ctx, socket, header.EnvelopeID); err != nil {
					return true, err
				}
				adapter.log("action-rejected")
				continue
			}
			if err := adapter.sink.Submit(ctx, candidate); err != nil {
				adapter.log("decision-rejected")
				if acknowledgement.IsTerminalDenial(err) {
					if ackErr := acknowledgeEnvelope(ctx, socket, header.EnvelopeID); ackErr != nil {
						return true, ackErr
					}
					continue
				}
				return true, err
			}
			if err := acknowledgeEnvelope(ctx, socket, header.EnvelopeID); err != nil {
				return true, err
			}
		default:
			if err := acknowledgeEnvelope(ctx, socket, header.EnvelopeID); err != nil {
				return true, err
			}
			adapter.log("envelope-ignored")
		}
	}
}

func (adapter *Adapter) recordRejection(ctx context.Context, raw []byte, reason string) error {
	digest := sha256.Sum256(raw)
	fingerprint := hex.EncodeToString(digest[:])
	rejection := acknowledgement.AdapterRejection{SourcePrincipal: rejectionSourcePrincipal(ctx, raw), AuthorityID: adapter.config.AuthorityID, AttemptDigest: "sha256:" + fingerprint, ReasonCode: reason, RejectedAt: adapter.clock().UTC().Truncate(time.Second)}
	return adapter.sink.Reject(ctx, rejection)
}

func rejectionSourcePrincipal(ctx context.Context, raw []byte) identity.Principal {
	unknown := identity.Principal{ID: acknowledgement.UnknownSourcePrincipalID, Method: acknowledgement.UnknownSourcePrincipalMode, Kind: identity.PrincipalPolicy}
	if len(raw) == 0 || len(raw) > MaxEnvelopeBytes || strictjson.Scan(ctx, raw, strictjson.Limits{MaxDepth: MaxJSONDepth}) != nil {
		return unknown
	}
	var envelope interactiveEnvelope
	if decodeClosed(raw, &envelope) != nil || envelope.Type != "interactive" || !validOpaqueID(envelope.Payload.Team.ID) || !validOpaqueID(envelope.Payload.User.ID) {
		return unknown
	}
	actor := sha256.Sum256([]byte("slack-actor-v1\x00" + envelope.Payload.Team.ID + "\x00" + envelope.Payload.User.ID))
	return identity.Principal{ID: "slack-actor-" + hex.EncodeToString(actor[:16]), Method: identity.SlackSocketModeMethod, Kind: identity.PrincipalHuman}
}

func acknowledgeEnvelope(ctx context.Context, socket Socket, envelopeID string) error {
	if envelopeID == "" {
		return nil
	}
	return socket.Acknowledge(ctx, envelopeID)
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
	if len(value) < 8 || len(value) > 4096 || !utf8.Valid(value) {
		return false
	}
	for _, character := range string(value) {
		if unicode.IsSpace(character) || unicode.IsControl(character) {
			return false
		}
	}
	return true
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
