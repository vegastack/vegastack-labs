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
	applyOrder   int
	sequence     *int
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
	if repo.sequence != nil {
		*repo.sequence++
		repo.applyOrder = *repo.sequence
	}
	value := repo.appliedValue
	value.ReferenceID = request.Stage.Reference.ReferenceID
	value.Status = request.Stage.Reference.Status
	value.MaterialVersion = request.Stage.Reference.MaterialVersion
	return value, nil
}

type recordingLifecycleVerifier struct {
	sequence     *int
	verifyOrder  int
	results      []credentialref.ConsumerVerification
	blockedError error
}

func (verifier *recordingLifecycleVerifier) Verify(context.Context, ExactStepBinding, credentialref.LifecycleBinding) ([]credentialref.ConsumerVerification, error) {
	if verifier.blockedError != nil {
		return nil, verifier.blockedError
	}
	if verifier.sequence != nil {
		*verifier.sequence++
		verifier.verifyOrder = *verifier.sequence
	}
	return verifier.results, nil
}

type countingGate struct {
	calls     int
	sequence  *int
	gateOrder int
}

func (gate *countingGate) VerifySecretStep(context.Context, generated.Plan, generated.PlanOperation) error {
	gate.calls++
	if gate.sequence != nil {
		*gate.sequence++
		gate.gateOrder = *gate.sequence
	}
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

func TestCredentialEffectStageSkipsGateAndAppendsInert(t *testing.T) {
	now := time.Date(2026, 9, 17, 0, 0, 0, 0, time.UTC)
	binding, lifecycleBinding := lifecycleEffectBinding(t, now, credentialref.ActionStage)
	lifecycleBinding.DraftID = stringPointerRun("draft-a")
	approval := approvedLifecycleApproval()
	approval.stored.Acknowledgement.PlanDigest = binding.Plan.PlanDigest
	repo := &fakeLifecycleRepository{binding: lifecycleBinding, draft: store.CredentialImportDraft{ConsumerID: "consumer-a", PurposeID: "deploy-a", TargetID: lifecycleBinding.TargetID, ResolverID: "native-a", CiphertextFingerprint: lifecycleFingerprint}}
	gate := &countingGate{}
	effect, err := NewCoreCredentialEffect(repo, approval, gate, &recordingLifecycleVerifier{}, UnavailableCredentialRecoveryVerifier{}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	result, err := effect.Execute(context.Background(), binding)
	if err != nil {
		t.Fatalf("stage effect failed: %v", err)
	}
	if result.Status != "succeeded" || gate.calls != 0 || repo.applied == nil {
		t.Fatalf("stage did not append inert without a gate: result=%+v gate=%d applied=%v", result, gate.calls, repo.applied != nil)
	}
	if repo.applied.Stage.Reference.Status != "staged" || repo.applied.Stage.Reference.ConsumerID != "consumer-a" {
		t.Fatalf("stage built the wrong target: %+v", repo.applied.Stage.Reference)
	}
}

func TestCredentialEffectActivationBlocksWithoutConsumerVerifier(t *testing.T) {
	now := time.Date(2026, 9, 17, 0, 0, 0, 0, time.UTC)
	binding, lifecycleBinding := lifecycleEffectBinding(t, now, credentialref.ActionActivate)
	approval := approvedLifecycleApproval()
	approval.stored.Acknowledgement.PlanDigest = binding.Plan.PlanDigest
	repo := &fakeLifecycleRepository{binding: lifecycleBinding, reference: generated.CredentialReference{ReferenceID: "reference-a", ConsumerID: "consumer-a", PurposeID: "deploy-a", TargetID: lifecycleBinding.TargetID, ResolverID: "native-a", MaterialVersion: "version-a", Fingerprint: lifecycleFingerprint, Status: "staged", RecoveryEpoch: 0}}
	effect, err := NewCoreCredentialEffect(repo, approval, &countingGate{}, UnavailableCredentialLifecycleVerifier{}, UnavailableCredentialRecoveryVerifier{}, func() time.Time { return now })
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

func TestCredentialEffectVerifierRunsBeforeAppend(t *testing.T) {
	now := time.Date(2026, 9, 17, 0, 0, 0, 0, time.UTC)
	binding, lifecycleBinding := lifecycleEffectBinding(t, now, credentialref.ActionActivate)
	approval := approvedLifecycleApproval()
	approval.stored.Acknowledgement.PlanDigest = binding.Plan.PlanDigest
	sequence := 0
	repo := &fakeLifecycleRepository{binding: lifecycleBinding, sequence: &sequence, reference: generated.CredentialReference{ReferenceID: "reference-a", ConsumerID: "consumer-a", PurposeID: "deploy-a", TargetID: lifecycleBinding.TargetID, ResolverID: "native-a", MaterialVersion: "version-a", Fingerprint: lifecycleFingerprint, Status: "staged", RecoveryEpoch: 0}}
	verifier := &recordingLifecycleVerifier{sequence: &sequence, results: []credentialref.ConsumerVerification{
		{ConsumerID: "consumer-a", ProfileID: "profile-a", RoleID: "role-a", MaterialVersion: "version-a", CiphertextFingerprint: lifecycleFingerprint, EvidenceDigest: lifecycleFingerprint, RestartObserved: true, Result: "verified", ReasonCode: "loaded"},
		{ConsumerID: "consumer-denied", ProfileID: "profile-b", RoleID: "role-b", MaterialVersion: "version-a", CiphertextFingerprint: lifecycleFingerprint, EvidenceDigest: lifecycleFingerprint, RestartObserved: false, Result: "denied", ReasonCode: "denied"},
	}}
	gate := &countingGate{sequence: &sequence}
	effect, err := NewCoreCredentialEffect(repo, approval, gate, verifier, UnavailableCredentialRecoveryVerifier{}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := effect.Execute(context.Background(), binding); err != nil {
		t.Fatalf("activation failed: %v", err)
	}
	// The gate, verifier and append all advance the same sequence counter, so a
	// regression that ran the gate after the verifier (or appended before either)
	// would be caught here, not silently pass (Finding F6).
	if gate.calls != 1 || gate.gateOrder == 0 || verifier.verifyOrder == 0 || repo.applyOrder == 0 {
		t.Fatalf("gate, verify and append must all run: gate=%d gateOrder=%d verify=%d apply=%d", gate.calls, gate.gateOrder, verifier.verifyOrder, repo.applyOrder)
	}
	if !(gate.gateOrder < verifier.verifyOrder && verifier.verifyOrder < repo.applyOrder) {
		t.Fatalf("order must be gate -> verify -> append: gate=%d verify=%d apply=%d", gate.gateOrder, verifier.verifyOrder, repo.applyOrder)
	}
	if repo.applied == nil || len(repo.applied.Verifications) != 2 {
		t.Fatalf("verification evidence not carried to the append: %+v", repo.applied)
	}
}

func stringPointerRun(value string) *string { return &value }
