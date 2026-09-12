package server

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/vegastack/vegastack-labs/internal/acknowledgement"
	"github.com/vegastack/vegastack-labs/internal/adapters/slack"
	"github.com/vegastack/vegastack-labs/internal/api"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
)

const maxSlackAcknowledgementConfigBytes = 32 << 10

type slackAcknowledgementProfile struct {
	WorkspaceID       string `json:"workspaceId"`
	SlackUserID       string `json:"slackUserId"`
	HumanID           string `json:"humanId"`
	AuthorityID       string `json:"authorityId"`
	ChannelID         string `json:"channelId"`
	ApproveActionID   string `json:"approveActionId"`
	RejectActionID    string `json:"rejectActionId"`
	AppTokenReference string `json:"appTokenReference"`
	BotTokenReference string `json:"botTokenReference"`
	NonceKeyReference string `json:"nonceKeyReference"`
}

type slackAcknowledgementRuntime struct {
	scopes     api.AcknowledgementScopeResolver
	publisher  api.AcknowledgementPublisher
	background BackgroundService
}

func composeSlackAcknowledgement(ctx context.Context, path string, ownerUID uint32, service *acknowledgement.Service) (slackAcknowledgementRuntime, error) {
	profile, err := loadSlackAcknowledgementProfile(ctx, path, ownerUID)
	if err != nil {
		return slackAcknowledgementRuntime{}, err
	}
	if service == nil || !authorization.ValidIdentifier(profile.NonceKeyReference) || profile.NonceKeyReference == profile.AppTokenReference || profile.NonceKeyReference == profile.BotTokenReference {
		return slackAcknowledgementRuntime{}, failure.New(generated.ErrorCodeInputInvalid, "slack-acknowledgement-config", false)
	}
	resolver, err := newSystemdCredentialResolver(ownerUID)
	if err != nil {
		return slackAcknowledgementRuntime{}, err
	}
	transport, err := slack.NewHTTPTransport(&http.Client{Timeout: 10 * time.Second})
	if err != nil {
		return slackAcknowledgementRuntime{}, err
	}
	adapter, err := slack.NewAdapter(slack.Config{
		AppTokenReference: credentialref.Reference{ID: profile.AppTokenReference, Consumer: "slack-acknowledgement"},
		BotTokenReference: credentialref.Reference{ID: profile.BotTokenReference, Consumer: "slack-acknowledgement"},
		WorkspaceID:       profile.WorkspaceID, SlackUserID: profile.SlackUserID, HumanID: profile.HumanID, AuthorityID: profile.AuthorityID,
		ChannelID: profile.ChannelID, ApproveActionID: profile.ApproveActionID, RejectActionID: profile.RejectActionID,
		ReconnectDelay: 250 * time.Millisecond, MaxReconnectDelay: 5 * time.Second,
	}, resolver, transport, service)
	if err != nil {
		return slackAcknowledgementRuntime{}, err
	}
	scopes := &slackAcknowledgementScopes{profile: profile, resolver: resolver, nonceKey: credentialref.Reference{ID: profile.NonceKeyReference, Consumer: "slack-acknowledgement"}}
	return slackAcknowledgementRuntime{scopes: scopes, publisher: adapter, background: adapter}, nil
}

func loadSlackAcknowledgementProfile(ctx context.Context, path string, ownerUID uint32) (slackAcknowledgementProfile, error) {
	if ctx == nil || path == "" {
		return slackAcknowledgementProfile{}, failure.New(generated.ErrorCodeInputInvalid, "slack-acknowledgement-config", false)
	}
	file, err := openProtectedSlackAcknowledgementProfile(path, ownerUID)
	if err != nil {
		return slackAcknowledgementProfile{}, failure.New(generated.ErrorCodePrerequisiteBlocked, "slack-acknowledgement-config", false)
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maxSlackAcknowledgementConfigBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > maxSlackAcknowledgementConfigBytes {
		return slackAcknowledgementProfile{}, failure.New(generated.ErrorCodeInputInvalid, "slack-acknowledgement-config", false)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var profile slackAcknowledgementProfile
	if decoder.Decode(&profile) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return slackAcknowledgementProfile{}, failure.New(generated.ErrorCodeInputInvalid, "slack-acknowledgement-config", false)
	}
	return profile, nil
}

type slackAcknowledgementScopes struct {
	profile  slackAcknowledgementProfile
	resolver slack.CredentialResolver
	nonceKey credentialref.Reference
}

func (scopes *slackAcknowledgementScopes) Resolve(ctx context.Context, request generated.AcknowledgementRequest) (acknowledgement.Scope, error) {
	if request.HumanID != scopes.profile.HumanID || request.AuthorityID != scopes.profile.AuthorityID {
		return acknowledgement.Scope{}, failure.New(generated.ErrorCodeAuthorizationDenied, "slack-acknowledgement-scope", false)
	}
	key, err := scopes.resolver.Resolve(ctx, scopes.nonceKey)
	if err != nil {
		return acknowledgement.Scope{}, err
	}
	defer zeroCredential(key)
	raw, err := json.Marshal(request)
	if err != nil {
		return acknowledgement.Scope{}, failure.New(generated.ErrorCodeInputInvalid, "slack-acknowledgement-request", false)
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("slack-acknowledgement-nonce-v1\x00"))
	_, _ = mac.Write(raw)
	nonce := hex.EncodeToString(mac.Sum(nil))
	return acknowledgement.Scope{Human: identity.Principal{ID: scopes.profile.HumanID, Method: identity.SlackSocketModeMethod, Kind: identity.PrincipalHuman}, AuthorityID: scopes.profile.AuthorityID, Nonce: nonce}, nil
}

func zeroCredential(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

var (
	_ BackgroundService            = (*slack.Adapter)(nil)
	_ api.AcknowledgementPublisher = (*slack.Adapter)(nil)
	_ slack.CandidateSink          = (*acknowledgement.Service)(nil)
)
