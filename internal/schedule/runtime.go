package schedule

import (
	"context"
	"encoding/hex"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/stateexport"
)

// AuthorityReader supplies current authority-bound observations. Specialized
// backup and audit requirements remain blocked until their own proof readers
// are composed; current control authority alone cannot stand in for them.
type AuthorityReader struct {
	Revisions interface {
		CurrentScheduleRevision(context.Context) (Revision, error)
	}
	Clock func() time.Time
}

func (reader AuthorityReader) CurrentObservationFingerprint(ctx context.Context, policy generated.ScheduledJobPolicy) (string, error) {
	revision, err := reader.Revisions.CurrentScheduleRevision(ctx)
	if err != nil {
		return "", err
	}
	_, sum, err := stateexport.CanonicalJSON(struct {
		PolicyID      string `json:"policyId"`
		Revision      int64  `json:"revision"`
		StateRevision int64  `json:"stateRevision"`
		RecoveryEpoch int64  `json:"recoveryEpoch"`
	}{policy.PolicyID, policy.Revision, revision.StateRevision, revision.RecoveryEpoch})
	if err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func (reader AuthorityReader) Current(ctx context.Context, requirements []PrerequisiteRequirement) ([]PrerequisiteStatus, error) {
	revision, err := reader.Revisions.CurrentScheduleRevision(ctx)
	if err != nil {
		return nil, err
	}
	now := time.Now
	if reader.Clock != nil {
		now = reader.Clock
	}
	statuses := make([]PrerequisiteStatus, len(requirements))
	for index, requirement := range requirements {
		state := "blocked"
		if requirement.Kind == "recovery-authority" && requirement.RecoveryEpoch == revision.RecoveryEpoch {
			state = "current"
		}
		statuses[index] = PrerequisiteStatus{Requirement: requirement, State: state, ObservedAt: now().UTC().Truncate(time.Second), RecoveryEpoch: revision.RecoveryEpoch}
	}
	return statuses, nil
}
