package recovery

import (
	"context"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/store"
)

func TestExactFenceWitnessBindsImmutablePlanAndExecution(t *testing.T) {
	installed, required, qualified, witness, now, _ := installedSourceFixture(t)
	admission := SourceAdmission{FormerHostID: witness.FormerHostID, FormerInstanceID: witness.FormerInstanceID, ReplacementHostID: witness.ReplacementHostID, ReplacementInstanceID: witness.ReplacementInstanceID, DraftID: witness.DraftID, CiphertextFingerprint: witness.CiphertextFingerprint, PriorEpoch: witness.PriorEpoch, NewEpoch: witness.NewEpoch, WitnessKeyID: installed.Pin.KeyID, WitnessInstanceID: installed.Pin.WitnessInstanceID, RecipientKeyID: installed.Pin.RecipientKeyID, WitnessPublicKey: installed.Pin.PublicKey, RecipientPublicKey: installed.Pin.RecipientPublicKey, AdminRootDigest: installed.Pin.adminRootDigest, FenceQualificationDigest: qualified.qualificationDigest, Requirements: required}
	source := VerifiedSource{Binding: generated.RestoreSourceBinding{PointID: "point-a", RecoveryEpoch: witness.PriorEpoch}}
	profile := store.GateAppliedProfile{ProfileID: "labs", ProfileVersion: "1.0.0", PolicyID: "policy-a", PolicyVersion: "1.0.0", RecoveryEpoch: witness.PriorEpoch}
	derived, err := AdmissionFenceRequirements(admission, profile, source, "build-a", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	requiredSet, err := RequiredFenceSet(derived, witness.SourceAdmissionDigest, witness.FenceQualificationDigest)
	if err != nil {
		t.Fatal(err)
	}
	binding := generated.RestoreBinding{FormerHostID: witness.FormerHostID, ReplacementHostID: witness.ReplacementHostID, RecoveryDraftID: witness.DraftID, CiphertextFingerprint: witness.CiphertextFingerprint, SourceAdmissionDigest: witness.SourceAdmissionDigest, FenceQualificationDigest: witness.FenceQualificationDigest, PlanDigest: witness.PlanDigest, RecoveryRunID: witness.RunID, RecoveryStepID: witness.StepID, RecoveryLeaseID: witness.LeaseID, RecoveryChallengeID: witness.ChallengeID, RecoveryReceiptID: witness.ReceiptID, PriorInstanceID: witness.FormerInstanceID, NewInstanceID: witness.ReplacementInstanceID, PriorRecoveryEpoch: witness.PriorEpoch, NextRecoveryEpoch: witness.NewEpoch, FenceSetDigest: requiredSet.FenceSetDigest}
	verifier := ExactFenceWitnessVerifier{Admissions: func(SourceAdmissionExpectation) (SourceAdmission, error) { return admission, nil }, Packages: func(context.Context, WitnessBinding) (InstalledPackage, error) { return installed, nil }, Qualifications: func(context.Context, []BoundaryRequirement, time.Time) (QualifiedAdapters, error) {
		return qualified, nil
	}, Clock: func() time.Time { return now }, ReleaseBuildID: "build-a", EvaluatorVersion: "1.0.0"}
	if _, err := verifier.Verify(context.Background(), binding, witness.StateRevision, profile, source); err != nil {
		t.Fatal(err)
	}
	binding.RecoveryLeaseID = "other-lease"
	if _, err := verifier.Verify(context.Background(), binding, witness.StateRevision, profile, source); err == nil {
		t.Fatal("witness for another exact lease accepted")
	}
}
