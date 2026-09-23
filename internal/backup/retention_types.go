package backup

import (
	"context"
	"time"
)

// RetentionLease is a bounded, separately authorized session.
type RetentionLease struct {
	LeaseID, RepositoryID          string
	RecoveryEpoch                  int64
	MaximumExpiresAt               time.Time
	MaxMutations, MaxMutationBytes int64
	PlannedSnapshotIDs             []string
}

type RetentionLeaseVerifier interface {
	VerifyRetentionLease(RetentionLease, time.Time) error
}

type RetainedMutationAttempt struct {
	MutationID, LeaseID, RepositoryID, MutationKind, ObjectType, ObjectName, Digest string
	Sequence, Bytes, RecoveryEpoch                                                  int64
}

type RetainedMutationOutcome struct {
	MutationID, LeaseID, ObjectType, ObjectName, QuarantineName string
	Status                                                      string
}

type RetainedMutationJournal interface {
	BeginRetainedMutation(context.Context, RetainedMutationAttempt) error
	FinishRetainedMutation(context.Context, RetainedMutationOutcome) error
}
