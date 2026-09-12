// Package acknowledgement owns provider-neutral human acknowledgement requests
// and their single-use terminal proofs. Provider interaction claims are reduced
// to these types by a typed adapter before they reach this package.
package acknowledgement

import (
	"context"
	"time"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
)

const (
	ActionApprove       = "approved"
	ActionReject        = "rejected"
	ExpiryPrincipalID   = "policy.acknowledgement-expiry"
	ExpiryPrincipalMode = "internal-policy"
)

type Scope struct {
	Human       identity.Principal
	AuthorityID string
	Nonce       string
}

type Candidate struct {
	Human         identity.Principal
	AuthorityID   string
	Action        string
	PlanID        string
	PlanDigest    string
	TargetDigest  string
	ReasonDigest  string
	Nonce         string
	StateRevision int64
	RecoveryEpoch int64
	ExpiresAt     time.Time
	DecidedAt     time.Time
}

type RequestCard struct {
	Request           generated.AcknowledgementRequest
	AcknowledgementID string
	Nonce             string
}

type Stored struct {
	Request         generated.AcknowledgementRequest
	Acknowledgement generated.Acknowledgement
	Consumed        bool
}

type CreateRecord struct {
	Request     generated.AcknowledgementRequest
	Pending     generated.Acknowledgement
	CreatedAt   time.Time
	Attribution audit.Attribution
}

type DecisionRecord struct {
	Expected    generated.AcknowledgementRequest
	Outcome     generated.Acknowledgement
	DecidedAt   time.Time
	Attribution audit.Attribution
}

// DenialRecord contains only fingerprints and stable identifiers. Raw provider
// payloads and nonces never cross into durable audit storage.
type DenialRecord struct {
	PlanID            string
	AcknowledgementID string
	AttemptDigest     string
	ReasonCode        string
	RejectedAt        time.Time
	Attribution       audit.Attribution
}

type Repository interface {
	Create(context.Context, CreateRecord) (Stored, bool, error)
	Get(context.Context, string) (Stored, error)
	Decide(context.Context, DecisionRecord) (Stored, bool, error)
	Consume(context.Context, string, time.Time) (Stored, bool, error)
	RecordDenial(context.Context, DenialRecord) error
}

type PlanReader interface {
	Get(context.Context, string) (generated.Plan, error)
	ValidateCurrent(context.Context, generated.Plan) error
}

type Authorizer interface {
	Authorize(context.Context, identity.Principal, authorization.Request) (authorization.Decision, error)
}
