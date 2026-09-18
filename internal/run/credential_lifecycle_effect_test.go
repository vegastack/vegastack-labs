package run

import (
	"context"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/store"
)

const lifecycleFingerprint = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

type fakeLifecycleRepository struct {
	binding      credentialref.LifecycleBinding
	reference    generated.CredentialReference
	draft        store.CredentialImportDraft
	applied      *store.CredentialLifecycleApplyRequest
	appliedValue generated.CredentialReference
}

func (repo *fakeLifecycleRepository) GetLifecycleBinding(context.Context, generated.Plan, string) (credentialref.LifecycleBinding, error) {
	return repo.binding, nil
}
func (repo *fakeLifecycleRepository) GetReference(context.Context, string) (generated.CredentialReference, error) {
	return repo.reference, nil
}
func (repo *fakeLifecycleRepository) LookupImportDraftByReference(context.Context, string, string, int64) (store.CredentialImportDraft, error) {
	return repo.draft, nil
}
func (repo *fakeLifecycleRepository) ApplyCredentialLifecycle(_ context.Context, request store.CredentialLifecycleApplyRequest) (generated.CredentialReference, error) {
	clone := request
	repo.applied = &clone
	value := repo.appliedValue
	value.ReferenceID = request.Stage.Reference.ReferenceID
	value.Status = request.Stage.Reference.Status
	value.MaterialVersion = request.Stage.Reference.MaterialVersion
	return value, nil
}

type recordingLifecycleVerifier struct {
	results      []credentialref.ConsumerVerification
	blockedError error
}

func (verifier *recordingLifecycleVerifier) Verify(context.Context, ExactStepBinding, credentialref.LifecycleBinding) ([]credentialref.ConsumerVerification, error) {
	if verifier.blockedError != nil {
		return nil, verifier.blockedError
	}
	return verifier.results, nil
}

type lifecycleFixtureGate struct{}

func (*lifecycleFixtureGate) VerifySecretStep(context.Context, generated.Plan, generated.PlanOperation) error {
	return nil
}

func lifecycleEffectBinding(t *testing.T, now time.Time, action credentialref.LifecycleAction) (ExactStepBinding, credentialref.LifecycleBinding) {
	t.Helper()
	plan := testPlan(now)
	plan.AuthorizationBranch = "human"
	plan.Operations[0].OperationType = string(action)
	plan.Operations[0].AdapterID = "core.credential"
	plan.Operations[0].InputDigest = lifecycleFingerprint
	plan.Operations[0].ArtifactDigest = lifecycleFingerprint
	target := plan.Operations[0].TargetID
	stepID, leaseID, runID := "step-a", "lease-a", "run-a"
	ackID := "ack-a"
	binding := ExactStepBinding{
		Plan:  plan,
		Run:   generated.Run{RunID: runID, PlanID: plan.PlanID, ExecutorMode: "central", StateRevision: plan.Binding.StateRevision, RecoveryEpoch: plan.Binding.RecoveryEpoch, AcknowledgementID: &ackID},
		Step:  generated.RunStep{StepID: stepID, OperationType: string(action), OperationID: plan.Operations[0].OperationID, AdapterID: "core.credential", TargetID: target, InputDigest: lifecycleFingerprint, ArtifactDigest: lifecycleFingerprint, EffectState: "intent-recorded"},
		Lease: generated.ExecutorLease{LeaseID: leaseID, Status: "active", StepID: stepID, RunID: runID, PlanID: plan.PlanID, PlanDigest: plan.PlanDigest, ArtifactDigest: lifecycleFingerprint, RecoveryEpoch: plan.Binding.RecoveryEpoch},
	}
	lifecycleBinding := credentialref.LifecycleBinding{
		OperationID: plan.Operations[0].OperationID, Action: action, ReferenceID: "reference-a",
		ConsumerIDs: []string{"consumer-a"}, MaterialVersion: "version-a", ResolverID: "native-a",
		TargetID: target, CiphertextFingerprint: lifecycleFingerprint, StateRevision: plan.Binding.StateRevision, RecoveryEpoch: plan.Binding.RecoveryEpoch,
	}
	if action == credentialref.ActionActivate {
		lifecycleBinding.RequiredDeniedConsumerIDs = []string{"consumer-denied"}
	}
	return binding, lifecycleBinding
}

func approvedLifecycleApproval() *fixedGateApproval {
	approval := &fixedGateApproval{}
	approval.stored.Consumed = true
	approval.stored.Acknowledgement.Status = "approved"
	approval.stored.Acknowledgement.AcknowledgementID = "ack-a"
	approval.stored.Acknowledgement.HumanID = "human-a"
	return approval
}

func TestCredentialEffectActivationBlocksWithoutConsumerVerifier(t *testing.T) {
	now := time.Date(2026, 9, 17, 0, 0, 0, 0, time.UTC)
	binding, lifecycleBinding := lifecycleEffectBinding(t, now, credentialref.ActionActivate)
	approval := approvedLifecycleApproval()
	approval.stored.Acknowledgement.PlanDigest = binding.Plan.PlanDigest
	repo := &fakeLifecycleRepository{binding: lifecycleBinding, reference: generated.CredentialReference{ReferenceID: "reference-a", ConsumerID: "consumer-a", PurposeID: "deploy-a", TargetID: lifecycleBinding.TargetID, ResolverID: "native-a", MaterialVersion: "version-a", Fingerprint: lifecycleFingerprint, Status: "staged", RecoveryEpoch: 0}}
	effect, err := NewCoreCredentialEffect(repo, approval, &lifecycleFixtureGate{}, UnavailableCredentialLifecycleVerifier{}, UnavailableCredentialRecoveryVerifier{}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := effect.Execute(context.Background(), binding); Code(err) != generated.ErrorCodePrerequisiteBlocked {
		t.Fatalf("activation admitted without a consumer verifier: %v", err)
	}
	if repo.applied != nil {
		t.Fatal("status changed without complete consumer verification")
	}
}
