package schedule

import (
	"errors"
	"time"
)

type PrerequisiteRequirement struct {
	Kind, SourceID, SubjectID, TargetID, PolicyID    string
	PolicyRevision, RecoveryEpoch, MaximumAgeSeconds int64
}
type PrerequisiteStatus struct {
	Requirement   PrerequisiteRequirement
	State         string
	ObservedAt    time.Time
	RecoveryEpoch int64
}

func RequireCurrent(requirements []PrerequisiteRequirement, statuses []PrerequisiteStatus, now time.Time) error {
	if len(requirements) == 0 || len(statuses) != len(requirements) {
		return errors.New("scheduled prerequisites missing")
	}
	wanted := make(map[PrerequisiteRequirement]bool, len(requirements))
	for _, requirement := range requirements {
		if wanted[requirement] {
			return errors.New("scheduled prerequisite duplicated")
		}
		wanted[requirement] = true
	}
	seen := make(map[PrerequisiteRequirement]bool, len(statuses))
	for _, status := range statuses {
		if !wanted[status.Requirement] || seen[status.Requirement] {
			return errors.New("scheduled prerequisite duplicated")
		}
		seen[status.Requirement] = true
		if status.State != "current" || status.RecoveryEpoch != status.Requirement.RecoveryEpoch || status.ObservedAt.IsZero() || now.UTC().Sub(status.ObservedAt.UTC()) > time.Duration(status.Requirement.MaximumAgeSeconds)*time.Second {
			return errors.New("scheduled prerequisite blocked")
		}
	}
	if len(seen) != len(wanted) {
		return errors.New("scheduled prerequisites missing")
	}
	return nil
}
