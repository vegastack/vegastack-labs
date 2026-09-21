package server

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/run"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type recoveryDraftFixture struct {
	draft store.CredentialImportDraft
	err   error
}

func (fixture recoveryDraftFixture) GetImportDraftByID(context.Context, string) (store.CredentialImportDraft, error) {
	return fixture.draft, fixture.err
}

type recoveryRevisionFixture struct{ token store.RevisionToken }

func (fixture recoveryRevisionFixture) CurrentRevision(context.Context) (store.RevisionToken, error) {
	return fixture.token, nil
}

type recoveryProofFixture struct {
	proof      RecoveryCustodyProof
	err        error
	called     int
	panicValue string
	hook       func()
}

func (fixture *recoveryProofFixture) VerifyRecovery(_ context.Context, _ RecoveryCustodyRequest) (RecoveryCustodyProof, error) {
	fixture.called++
	if fixture.hook != nil {
		fixture.hook()
	}
	if fixture.panicValue != "" {
		panic(fixture.panicValue)
	}
	return fixture.proof, fixture.err
}

func recoveryCustodyFixture(t *testing.T) (run.ExactStepBinding, credentialref.LifecycleBinding, store.CredentialImportDraft, *recoveryProofFixture) {
	t.Helper()
	digest := "sha256:" + strings.Repeat("a", 64)
	custody := "sha256:" + strings.Repeat("b", 64)
	fence := "sha256:" + strings.Repeat("c", 64)
	draftID, consumer, purpose := "draft-a", "consumer-a", "purpose-a"
	state, prior := int64(5), int64(1)
	lifecycle := credentialref.LifecycleBinding{
		OperationID: "operation-a", Action: credentialref.ActionRecover,
		DraftID: &draftID, ImportDraftStateRevision: &state, ImportDraftConsumerID: &consumer, ImportDraftPurposeID: &purpose,
		ReferenceID: "reference-a", ConsumerIDs: []string{consumer}, MaterialVersion: "version-a", ResolverID: "native-systemd", TargetID: "target-a",
		CiphertextFingerprint: digest, StateRevision: 6, RecoveryEpoch: 2, PriorRecoveryEpoch: &prior,
		CustodyProofDigest: &custody, FormerControllerFenceDigest: &fence,
	}
	if !credentialref.ValidLifecycleBinding(lifecycle) {
		t.Fatal("fixture binding invalid")
	}
	draft := store.CredentialImportDraft{DraftID: draftID, ReferenceID: lifecycle.ReferenceID, ConsumerID: consumer, PurposeID: purpose,
		TargetID: lifecycle.TargetID, ResolverID: lifecycle.ResolverID, MaterialVersion: lifecycle.MaterialVersion,
		CiphertextName: "credential-native-a", CiphertextFingerprint: digest, StateRevision: state, RecoveryEpoch: lifecycle.RecoveryEpoch}
	step := run.ExactStepBinding{}
	step.Plan.PlanID, step.Plan.PlanDigest = "plan-a", digest
	step.Plan.Binding.StateRevision, step.Plan.Binding.RecoveryEpoch = lifecycle.StateRevision, lifecycle.RecoveryEpoch
	step.Run.RunID, step.Run.RecoveryEpoch = "run-a", lifecycle.RecoveryEpoch
	step.Step.StepID, step.Step.OperationID, step.Step.OperationType = "step-a", lifecycle.OperationID, string(lifecycle.Action)
	step.Step.TargetID, step.Step.ArtifactDigest = lifecycle.TargetID, digest
	step.Lease.LeaseID, step.Lease.RecoveryEpoch = "lease-a", lifecycle.RecoveryEpoch
	proof := &recoveryProofFixture{proof: RecoveryCustodyProof{DraftID: draftID, CiphertextName: draft.CiphertextName, CiphertextFingerprint: digest,
		ReferenceID: lifecycle.ReferenceID, TargetID: lifecycle.TargetID, MaterialVersion: lifecycle.MaterialVersion,
		PriorRecoveryEpoch: prior, RecoveryEpoch: lifecycle.RecoveryEpoch, CustodyProofDigest: custody, FormerControllerFenceDigest: fence,
		ReplacementHostKeyDigest: digest, SourceEvidenceDigest: digest}}
	return step, lifecycle, draft, proof
}

func TestRecoveryCustodyContractBindsExactDraftAndCurrentEpoch(t *testing.T) {
	step, lifecycle, draft, proof := recoveryCustodyFixture(t)
	verifier, err := NewRecoveryCustodyVerifier(recoveryDraftFixture{draft: draft}, recoveryRevisionFixture{token: store.RevisionToken{StateRevision: 6, RecoveryEpoch: 2}}, proof)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := verifier.Verify(context.Background(), step, lifecycle)
	if err != nil || !credentialref.ValidRecoveryVerification(lifecycle, evidence) || proof.called != 1 {
		t.Fatalf("exact metadata proof rejected: %v, calls=%d", err, proof.called)
	}
	if evidence.RecoveryEpoch != 2 || evidence.PriorRecoveryEpoch != 1 {
		t.Fatal("verifier changed externally established epoch")
	}
}

func TestRecoveryCustodyContractRejectsMissingAndOldProof(t *testing.T) {
	step, lifecycle, draft, proof := recoveryCustodyFixture(t)
	for name, token := range map[string]store.RevisionToken{
		"old epoch":    {StateRevision: 6, RecoveryEpoch: 1},
		"future epoch": {StateRevision: 6, RecoveryEpoch: 3},
	} {
		t.Run(name, func(t *testing.T) {
			verifier, _ := NewRecoveryCustodyVerifier(recoveryDraftFixture{draft: draft}, recoveryRevisionFixture{token: token}, proof)
			_, err := verifier.Verify(context.Background(), step, lifecycle)
			stable, _ := failure.As(err)
			if stable == nil || stable.Code != generated.ErrorCodeRecoveryEpochMismatch || proof.called != 0 {
				t.Fatalf("wrong current epoch reached source: %v, calls=%d", err, proof.called)
			}
		})
	}
	verifier, _ := NewRecoveryCustodyVerifier(recoveryDraftFixture{draft: draft}, recoveryRevisionFixture{token: store.RevisionToken{StateRevision: 6, RecoveryEpoch: 2}}, proof)
	proof.err = errors.New("private-custody-canary")
	_, err := verifier.Verify(context.Background(), step, lifecycle)
	stable, _ := failure.As(err)
	if stable == nil || stable.Code != generated.ErrorCodeRecoveryRequired || strings.Contains(err.Error(), "private-custody-canary") {
		t.Fatalf("missing proof was not redacted: %v", err)
	}
	proof.err = nil
	proof.proof.DraftID = "draft-other"
	_, err = verifier.Verify(context.Background(), step, lifecycle)
	stable, _ = failure.As(err)
	if stable == nil || stable.Code != generated.ErrorCodeRecoveryRequired {
		t.Fatalf("foreign draft proof accepted: %v", err)
	}
}

func TestRecoveryCustodyContractRejectsOldOrChangedDraftBeforeProof(t *testing.T) {
	step, lifecycle, draft, proof := recoveryCustodyFixture(t)
	for name, mutate := range map[string]func(*store.CredentialImportDraft){
		"old epoch":               func(d *store.CredentialImportDraft) { d.RecoveryEpoch = 1 },
		"foreign draft":           func(d *store.CredentialImportDraft) { d.DraftID = "draft-foreign" },
		"foreign fingerprint":     func(d *store.CredentialImportDraft) { d.CiphertextFingerprint = "sha256:" + strings.Repeat("e", 64) },
		"foreign origin revision": func(d *store.CredentialImportDraft) { d.StateRevision++ },
	} {
		t.Run(name, func(t *testing.T) {
			changed := draft
			mutate(&changed)
			proof.called = 0
			verifier, _ := NewRecoveryCustodyVerifier(recoveryDraftFixture{draft: changed}, recoveryRevisionFixture{token: store.RevisionToken{StateRevision: 6, RecoveryEpoch: 2}}, proof)
			_, err := verifier.Verify(context.Background(), step, lifecycle)
			if err == nil || proof.called != 0 {
				t.Fatalf("changed draft reached independent source: %v, calls=%d", err, proof.called)
			}
		})
	}
}

func TestRecoveryCustodyContractRedactsPanicAndCancel(t *testing.T) {
	step, lifecycle, draft, proof := recoveryCustodyFixture(t)
	verifier, _ := NewRecoveryCustodyVerifier(recoveryDraftFixture{draft: draft}, recoveryRevisionFixture{token: store.RevisionToken{StateRevision: 6, RecoveryEpoch: 2}}, proof)
	proof.panicValue = "private-custody-canary"
	_, err := verifier.Verify(context.Background(), step, lifecycle)
	stable, _ := failure.As(err)
	if stable == nil || stable.Code != generated.ErrorCodeRecoveryRequired || strings.Contains(err.Error(), proof.panicValue) {
		t.Fatalf("source panic leaked or admitted: %v", err)
	}
	proof.panicValue = ""
	ctx, cancel := context.WithCancel(context.Background())
	proof.hook = cancel
	_, err = verifier.Verify(ctx, step, lifecycle)
	stable, _ = failure.As(err)
	if stable == nil || stable.Code != generated.ErrorCodeRecoveryRequired {
		t.Fatalf("post-source cancellation admitted: %v", err)
	}
}
