package schedule

import (
	"testing"
	"time"
)

func TestRequireCurrentRejectsIncompleteAndUnexpectedSets(t *testing.T) {
	now := time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC)
	first := PrerequisiteRequirement{Kind: "recovery-authority", SourceID: "source-a", SubjectID: "subject-a", TargetID: "target-a", PolicyID: "policy-a", PolicyRevision: 1, RecoveryEpoch: 2, MaximumAgeSeconds: 60}
	second := first
	second.Kind = "local-backup-qualification"
	current := func(requirement PrerequisiteRequirement) PrerequisiteStatus {
		return PrerequisiteStatus{Requirement: requirement, State: "current", ObservedAt: now, RecoveryEpoch: requirement.RecoveryEpoch}
	}
	if RequireCurrent([]PrerequisiteRequirement{first, second}, []PrerequisiteStatus{current(first)}, now) == nil {
		t.Fatal("incomplete prerequisite subset accepted")
	}
	unexpected := second
	unexpected.Kind = "audit-chain-current"
	if RequireCurrent([]PrerequisiteRequirement{first, second}, []PrerequisiteStatus{current(first), current(unexpected)}, now) == nil {
		t.Fatal("unexpected prerequisite substituted")
	}
	if err := RequireCurrent([]PrerequisiteRequirement{first, second}, []PrerequisiteStatus{current(first), current(second)}, now); err != nil {
		t.Fatalf("complete prerequisite set rejected: %v", err)
	}
}
