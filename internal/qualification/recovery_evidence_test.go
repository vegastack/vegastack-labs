package qualification

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"testing"
)

// This tests cross-binding predicates only; it is not native producer evidence.
func recoveryEvidenceFixture() (ProducerExecution, ReplacementRecoveryEvidence) {
	d := hostaction.Digest("synthetic-cross-binding")
	plan, run, restore := "commit-plan", "commit-run", "restore-plan"
	source := generated.RestoreSourceBinding{PointID: "point", ManifestDigest: d}
	continuity := generated.HostReplacementContinuityReference{ReplacementID: "replacement", Digest: d, SourcePointID: "point", SourceBindingDigest: hostaction.Digest(source), SourceAliasHighWatermark: 1, CurrentAliasHighWatermark: 2}
	binding := generated.RestoreBinding{PlanID: restore, Source: source, FormerHostID: "former", ReplacementHostID: "new", PriorInstanceID: "prior", NewInstanceID: "current", NextRecoveryEpoch: 1, CanaryRunID: "canary", ReplacementContinuity: &continuity}
	q := generated.HostReplacementRequest{Operation: "commit", RestorationClass: "control-database", ReplacementID: "replacement", OldHostID: "former", NewHostID: "new", OldIdentityDigest: hostaction.Digest("old"), NewIdentityDigest: hostaction.Digest("new"), ProfileID: "debian", ProfileLockDigest: d, ProposedRoleBindingDigest: d, Source: &generated.HostReplacementSourceReference{PointID: "point", SourceBindingDigest: hostaction.Digest(source)}, AliasBindings: []generated.HostReplacementAliasBinding{{AliasID: "alias", OwnerRevision: 1, OwnershipGeneration: 1}}}
	e := ProducerExecution{Reference: generated.NativeProducerReference{ScenarioID: "replacement-recovery", HostID: "new", PlanID: plan, PlanDigest: d, RunID: run, StepID: "step", LeaseID: "lease"}, Plan: generated.Plan{PlanID: plan, PlanDigest: d, Binding: generated.PlanBinding{RecoveryEpoch: 1}, HostReplacement: &q}, Receipt: generated.ExecutionReceipt{PlanID: plan, PlanDigest: d, RunID: run, StepID: "step", LeaseID: "lease", RecoveryEpoch: 1, Status: "succeeded"}}
	state := generated.HostReplacementState{ReplacementID: q.ReplacementID, OldHostID: q.OldHostID, NewHostID: q.NewHostID, OldIdentityDigest: q.OldIdentityDigest, NewIdentityDigest: q.NewIdentityDigest, RoleBindingDigest: d, RoleIntentRevision: 1, RecoveryEpoch: 1, Status: "committed", RestorationClass: "control-database", PlanID: &plan, RunID: &run, RestorePlanID: &restore, RestorationReceiptDigest: hostaction.Digest(binding), ContinuityDigest: d, AliasBindings: []generated.HostReplacementAliasBinding{{AliasID: "alias", OwnerHostID: "new", OwnerIdentityDigest: q.NewIdentityDigest, OwnerRevision: 3, OwnershipGeneration: 2}}}
	return e, ReplacementRecoveryEvidence{CurrentProfileID: q.ProfileID, CurrentProfileLockDigest: d, Binding: binding, Replacement: state, Continuity: continuity, CanaryDigest: d, CanaryRunID: "canary", CanaryEventID: 1, VerifiedAt: "2026-10-09T12:00:00Z"}
}
func TestReplacementRecoveryEvidenceCrossBindings(t *testing.T) {
	e, v := recoveryEvidenceFixture()
	if err := ValidateReplacementRecoveryEvidence(e, v); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*ProducerExecution, *ReplacementRecoveryEvidence){
		"stateless": func(e *ProducerExecution, v *ReplacementRecoveryEvidence) {
			e.Plan.HostReplacement.RestorationClass = "stateless-role"
		},
		"wrong-instance": func(e *ProducerExecution, v *ReplacementRecoveryEvidence) {
			v.Binding.NewInstanceID = v.Binding.PriorInstanceID
		},
		"epoch-reused":      func(e *ProducerExecution, v *ReplacementRecoveryEvidence) { v.Binding.NextRecoveryEpoch = 0 },
		"missing-canary":    func(e *ProducerExecution, v *ReplacementRecoveryEvidence) { v.CanaryEventID = 0 },
		"other-canary":      func(e *ProducerExecution, v *ReplacementRecoveryEvidence) { v.CanaryRunID = "other" },
		"source-transplant": func(e *ProducerExecution, v *ReplacementRecoveryEvidence) { v.Binding.Source.PointID = "other" },
		"lost-continuity":   func(e *ProducerExecution, v *ReplacementRecoveryEvidence) { v.Binding.ReplacementContinuity = nil },
		"alias-not-transferred": func(e *ProducerExecution, v *ReplacementRecoveryEvidence) {
			v.Replacement.AliasBindings[0].OwnerHostID = "former"
		},
		"same-identity": func(e *ProducerExecution, v *ReplacementRecoveryEvidence) {
			v.Replacement.NewIdentityDigest = v.Replacement.OldIdentityDigest
		},
		"different-profile": func(e *ProducerExecution, v *ReplacementRecoveryEvidence) { v.CurrentProfileID = "other" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			e, v := recoveryEvidenceFixture()
			mutate(&e, &v)
			if ValidateReplacementRecoveryEvidence(e, v) == nil {
				t.Fatal("mismatched recovered authority accepted")
			}
		})
	}
}
