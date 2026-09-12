package slack

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"time"

	"github.com/vegastack/vegastack-labs/internal/acknowledgement"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/strictjson"
)

type envelopeHeader struct {
	EnvelopeID string `json:"envelope_id"`
	Type       string `json:"type"`
}

type interactiveEnvelope struct {
	EnvelopeID string `json:"envelope_id"`
	Type       string `json:"type"`
	Payload    struct {
		Type string `json:"type"`
		Team struct {
			ID string `json:"id"`
		} `json:"team"`
		User struct {
			ID string `json:"id"`
		} `json:"user"`
		Actions []struct {
			ActionID string `json:"action_id"`
			Value    string `json:"value"`
		} `json:"actions"`
	} `json:"payload"`
}

type actionBinding struct {
	PlanID        string `json:"planId"`
	PlanDigest    string `json:"planDigest"`
	TargetDigest  string `json:"targetDigest"`
	ReasonDigest  string `json:"reasonDigest"`
	Nonce         string `json:"nonce"`
	StateRevision int64  `json:"stateRevision"`
	RecoveryEpoch int64  `json:"recoveryEpoch"`
	ExpiresAt     string `json:"expiresAt"`
}

var opaqueIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$`)

func decodeHeader(ctx context.Context, raw []byte) (envelopeHeader, error) {
	var header envelopeHeader
	if len(raw) == 0 || len(raw) > MaxEnvelopeBytes || strictjson.Scan(ctx, raw, strictjson.Limits{MaxDepth: MaxJSONDepth}) != nil || json.Unmarshal(raw, &header) != nil || header.Type == "" {
		return envelopeHeader{}, slackError(generated.ErrorCodeInputInvalid, "slack-envelope", false)
	}
	if header.EnvelopeID != "" && !validOpaqueID(header.EnvelopeID) {
		return envelopeHeader{}, slackError(generated.ErrorCodeInputInvalid, "slack-envelope", false)
	}
	return header, nil
}

func decodeCandidate(ctx context.Context, config Config, raw []byte, receivedAt time.Time) (acknowledgement.Candidate, error) {
	if len(raw) == 0 || len(raw) > MaxEnvelopeBytes || strictjson.Scan(ctx, raw, strictjson.Limits{MaxDepth: MaxJSONDepth}) != nil {
		return acknowledgement.Candidate{}, slackError(generated.ErrorCodeInputInvalid, "slack-action", false)
	}
	var envelope interactiveEnvelope
	if decodeClosed(raw, &envelope) != nil || envelope.Type != "interactive" || envelope.Payload.Type != "block_actions" || !validOpaqueID(envelope.EnvelopeID) || envelope.Payload.Team.ID != config.WorkspaceID || envelope.Payload.User.ID != config.SlackUserID || len(envelope.Payload.Actions) != 1 {
		return acknowledgement.Candidate{}, slackError(generated.ErrorCodeAuthorizationDenied, "slack-action", false)
	}
	action := envelope.Payload.Actions[0]
	decision := ""
	switch action.ActionID {
	case config.ApproveActionID:
		decision = acknowledgement.ActionApprove
	case config.RejectActionID:
		decision = acknowledgement.ActionReject
	default:
		return acknowledgement.Candidate{}, slackError(generated.ErrorCodeAuthorizationDenied, "slack-action", false)
	}
	if len(action.Value) == 0 || len(action.Value) > 16<<10 || strictjson.Scan(ctx, []byte(action.Value), strictjson.Limits{MaxDepth: 4}) != nil {
		return acknowledgement.Candidate{}, slackError(generated.ErrorCodeInputInvalid, "slack-action", false)
	}
	var binding actionBinding
	if decodeClosed([]byte(action.Value), &binding) != nil {
		return acknowledgement.Candidate{}, slackError(generated.ErrorCodeInputInvalid, "slack-action", false)
	}
	expiresAt, err := time.Parse(time.RFC3339, binding.ExpiresAt)
	if err != nil || expiresAt.Location() != time.UTC || receivedAt.Location() != time.UTC {
		return acknowledgement.Candidate{}, slackError(generated.ErrorCodeInputInvalid, "slack-action", false)
	}
	return acknowledgement.Candidate{Human: identity.Principal{ID: config.HumanID, Method: identity.SlackSocketModeMethod, Kind: identity.PrincipalHuman}, AuthorityID: config.AuthorityID, Action: decision, PlanID: binding.PlanID, PlanDigest: binding.PlanDigest, TargetDigest: binding.TargetDigest, ReasonDigest: binding.ReasonDigest, Nonce: binding.Nonce, StateRevision: binding.StateRevision, RecoveryEpoch: binding.RecoveryEpoch, ExpiresAt: expiresAt, DecidedAt: receivedAt}, nil
}

func decodeClosed(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON value")
	}
	return nil
}

func validOpaqueID(value string) bool {
	return opaqueIDPattern.MatchString(value)
}
