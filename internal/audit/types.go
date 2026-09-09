// Package audit defines provider-neutral, bounded values for canonical audit
// events and destination-neutral durable outbox state.
package audit

import (
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/identity"
)

const (
	EventSchema         = "vegastack-labs.dev/audit-event"
	EventSchemaVersion  = "1.0.0"
	OutboxSchema        = "vegastack-labs.dev/outbox-record-data"
	OutboxSchemaVersion = "1.0.0"
	MaxDeliveryAttempts = 8
	InitialRetryDelay   = 30 * time.Second
	MaxRetryDelay       = time.Hour
)

type EventID int64
type OutboxID int64
type Fingerprint string
type EventType string
type TargetKind string
type DestinationID string

type AgentMetadata struct {
	Name      string
	SessionID string
}

type Attribution struct {
	AuthenticatedPrincipalID     string
	AuthenticatedPrincipalMethod string
	ResponsibleHumanPrincipalID  *string
	Agent                        *AgentMetadata
}

type Target struct {
	Kind TargetKind `json:"kind"`
	ID   string     `json:"id"`
}

type EventDraft struct {
	Type          EventType
	CorrelationID string
	CausationID   *EventID
	CorrectionOf  *EventID
	Attribution   Attribution
	Target        Target
	Before        *Fingerprint
	After         *Fingerprint
}

type OutboxRequirement struct {
	Destination DestinationID
	Enabled     bool
}

type IntentKey struct {
	Scope         string
	KeyDigest     Fingerprint
	RequestDigest Fingerprint
}

type Event struct {
	Schema          string       `json:"schema"`
	SchemaVersion   string       `json:"schemaVersion"`
	EventID         EventID      `json:"eventId"`
	OccurredAt      string       `json:"occurredAt"`
	RecoveryEpoch   int64        `json:"recoveryEpoch"`
	StateRevision   int64        `json:"stateRevision"`
	Type            EventType    `json:"type"`
	CorrelationID   string       `json:"correlationId"`
	CausationID     *EventID     `json:"causationEventId"`
	CorrectionOf    *EventID     `json:"correctionOfEventId"`
	PrincipalID     string       `json:"principalId"`
	PrincipalMethod string       `json:"principalMethod"`
	HumanID         *string      `json:"responsibleHumanPrincipalId"`
	AgentName       *string      `json:"agentName"`
	AgentSessionID  *string      `json:"agentSessionId"`
	AgentSource     *string      `json:"agentSource"`
	Target          Target       `json:"target"`
	Before          *Fingerprint `json:"beforeFingerprint"`
	After           *Fingerprint `json:"afterFingerprint"`
}

type OutboxStatus string

const (
	OutboxPending    OutboxStatus = "pending"
	OutboxRetryWait  OutboxStatus = "retry_wait"
	OutboxPaused     OutboxStatus = "paused"
	OutboxDelivered  OutboxStatus = "delivered"
	OutboxDeadLetter OutboxStatus = "dead_letter"
)

type DeliveryErrorCode string

const (
	DestinationUnavailable DeliveryErrorCode = "DESTINATION_UNAVAILABLE"
	DeliveryRejected       DeliveryErrorCode = "DELIVERY_REJECTED"
	PayloadInvalid         DeliveryErrorCode = "PAYLOAD_INVALID"
	DeliveryInterrupted    DeliveryErrorCode = "INTERRUPTED"
)

type OutboxRecord struct {
	OutboxID       OutboxID
	EventID        EventID
	Destination    DestinationID
	PayloadSchema  string
	PayloadVersion string
	PayloadSHA256  Fingerprint
	DedupeSHA256   Fingerprint
	Status         OutboxStatus
	AttemptCount   int
	MaxAttempts    int
	NextAttemptAt  *time.Time
	LastErrorCode  *DeliveryErrorCode
	CreatedAt      time.Time
	UpdatedAt      time.Time
	DeliveredAt    *time.Time
}

type OutboxAttempt struct {
	OutboxID        OutboxID
	ExpectedAttempt int
	Delivered       bool
	Retryable       bool
	ErrorCode       DeliveryErrorCode
	AttemptedAt     time.Time
}

var (
	fingerprintPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	eventTypePattern   = regexp.MustCompile(`^[a-z][a-z0-9]*(\.[a-z][a-z0-9-]*){1,5}$`)
	tokenPattern       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]*$`)
)

var errInvalid = errors.New("invalid bounded audit value")

func NewAttribution(authenticated identity.Principal, responsibleHuman *identity.Principal, agent *AgentMetadata) (Attribution, error) {
	if !validToken(authenticated.ID, 128) || !validToken(authenticated.Method, 64) {
		return Attribution{}, errInvalid
	}
	result := Attribution{AuthenticatedPrincipalID: authenticated.ID, AuthenticatedPrincipalMethod: authenticated.Method}
	if responsibleHuman != nil {
		if !validToken(responsibleHuman.ID, 128) || !validToken(responsibleHuman.Method, 64) {
			return Attribution{}, errInvalid
		}
		value := responsibleHuman.ID
		result.ResponsibleHumanPrincipalID = &value
	}
	if agent != nil {
		if !validToken(agent.Name, 64) || !validToken(agent.SessionID, 128) {
			return Attribution{}, errInvalid
		}
		copy := *agent
		result.Agent = &copy
	}
	return result, nil
}

func ValidateEventDraft(draft EventDraft) error {
	if len(draft.Type) > 96 || !eventTypePattern.MatchString(string(draft.Type)) ||
		!validToken(draft.CorrelationID, 128) ||
		!validToken(string(draft.Target.Kind), 64) || !validToken(draft.Target.ID, 128) ||
		!validToken(draft.Attribution.AuthenticatedPrincipalID, 128) || !validToken(draft.Attribution.AuthenticatedPrincipalMethod, 64) {
		return errInvalid
	}
	if (draft.CausationID != nil && *draft.CausationID <= 0) || (draft.CorrectionOf != nil && *draft.CorrectionOf <= 0) {
		return errInvalid
	}
	if draft.Attribution.ResponsibleHumanPrincipalID != nil && !validToken(*draft.Attribution.ResponsibleHumanPrincipalID, 128) {
		return errInvalid
	}
	if draft.Attribution.Agent != nil && (!validToken(draft.Attribution.Agent.Name, 64) || !validToken(draft.Attribution.Agent.SessionID, 128)) {
		return errInvalid
	}
	if (draft.Before != nil && !ValidFingerprint(*draft.Before)) || (draft.After != nil && !ValidFingerprint(*draft.After)) {
		return errInvalid
	}
	return nil
}

func ValidateIntentKey(key IntentKey) error {
	if !validToken(key.Scope, 96) || !ValidFingerprint(key.KeyDigest) || !ValidFingerprint(key.RequestDigest) {
		return errInvalid
	}
	return nil
}

func ValidateOutboxRequirements(requirements []OutboxRequirement) error {
	if len(requirements) > 32 {
		return errInvalid
	}
	seen := make(map[DestinationID]struct{}, len(requirements))
	for _, requirement := range requirements {
		if !validToken(string(requirement.Destination), 96) {
			return errInvalid
		}
		if _, exists := seen[requirement.Destination]; exists {
			return errInvalid
		}
		seen[requirement.Destination] = struct{}{}
	}
	return nil
}

func ValidFingerprint(value Fingerprint) bool {
	return fingerprintPattern.MatchString(string(value))
}

func ValidDeliveryErrorCode(code DeliveryErrorCode) bool {
	switch code {
	case DestinationUnavailable, DeliveryRejected, PayloadInvalid, DeliveryInterrupted:
		return true
	default:
		return false
	}
}

func validToken(value string, maximum int) bool {
	if len(value) == 0 || len(value) > maximum || !tokenPattern.MatchString(value) {
		return false
	}
	lower := strings.ToLower(value)
	for _, prefix := range []string{"github_pat_", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "sk-", "xoxb-", "xoxp-", "akia"} {
		if strings.HasPrefix(lower, prefix) {
			return false
		}
	}
	return true
}

func RetryDelay(attempt int) time.Duration {
	if attempt <= 0 {
		return 0
	}
	delay := InitialRetryDelay
	for current := 1; current < attempt && delay < MaxRetryDelay; current++ {
		delay *= 2
		if delay > MaxRetryDelay {
			delay = MaxRetryDelay
		}
	}
	return delay
}
