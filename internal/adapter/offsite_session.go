package adapter

import (
	"context"
	"time"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
)

type RetentionRule struct {
	RuleID string
	Prefix string
}

type RetentionObservation struct {
	GenerationID, RuleDigest                      string
	ProtectedRules                                []RetentionRule
	MutablePrefixes                               []string
	RuleCount, RuleLimit, RetainedGenerations     int
	AvailableBytes, AvailablePUTs, AvailableLISTs int64
	ObservedAt                                    time.Time
	IndefiniteProtection                          bool
	ProofClass                                    string // fixture or qualified-provider
}

type SessionRequest struct {
	ParentReferenceID, ParentFingerprint string
	RunID, StepID, PointID, GenerationID string
	Prefix                               string
	Actions                              []string
	RecoveryEpoch                        int64
	Deadline                             time.Time
	TTL                                  time.Duration
}

type ScopedS3Session struct {
	AccessKeyID, SecretAccessKey, SessionToken []byte
	ExpiresAt                                  time.Time
}

type SessionIssuer interface {
	Issue(context.Context, SessionRequest, *credentialref.Value) (ScopedS3Session, error)
}
