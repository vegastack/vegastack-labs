package schedule

import (
	"errors"
	"time"
)

type PrerequisiteRequirement struct {
	Kind, SubjectID, PolicyID                        string
	PolicyRevision, RecoveryEpoch, MaximumAgeSeconds int64
}
type PrerequisiteStatus struct {
	Requirement   PrerequisiteRequirement
	State         string
	ObservedAt    time.Time
	RecoveryEpoch int64
}

func RequireCurrent(statuses []PrerequisiteStatus, now time.Time) error {
	for _, status := range statuses {
		if status.State != "current" || status.RecoveryEpoch != status.Requirement.RecoveryEpoch || status.ObservedAt.IsZero() || now.UTC().Sub(status.ObservedAt.UTC()) > time.Duration(status.Requirement.MaximumAgeSeconds)*time.Second {
			return errors.New("scheduled prerequisite blocked")
		}
	}
	return nil
}
