//go:build linux

package store

import (
	"context"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

func lifecycleStageBinding() credentialref.LifecycleBinding {
	return credentialref.LifecycleBinding{
		OperationID:           "operation-a",
		Action:                credentialref.ActionStage,
		DraftID:               stringPointer("draft-a"),
		ReferenceID:           "ref-a",
		ConsumerIDs:           []string{"consumer-a"},
		MaterialVersion:       "version-a",
		ResolverID:            "native-a",
		TargetID:              "service-a",
		CiphertextFingerprint: testDigest,
		StateRevision:         1,
		RecoveryEpoch:         0,
	}
}

func stringPointer(value string) *string { return &value }

func lifecycleStageRequest(binding credentialref.LifecycleBinding) CredentialLifecycleApplyRequest {
	reference := generated.CredentialReference{
		Schema: generated.SchemaIDCredentialReference, SchemaVersion: "1.1.0",
		ReferenceID: binding.ReferenceID, ConsumerID: "consumer-a", PurposeID: "deploy-a",
		TargetID: binding.TargetID, ResolverID: binding.ResolverID, MaterialVersion: binding.MaterialVersion,
		Fingerprint: binding.CiphertextFingerprint, Status: "staged", StateRevision: 1, RecoveryEpoch: 0,
		VerifiedConsumerIDs: []string{},
	}
	stage := CredentialStageRequest{
		Reference: reference, DeclarationID: "declaration-a", DeclarationRevision: 1,
		PlanID: "plan-a", PlanDigest: testDigest, RunID: "run-a", StepID: "step-a", LeaseID: "lease-a", HumanID: "principal-test-1",
		Expected: RevisionToken{StateRevision: 0, RecoveryEpoch: 0}, Attribution: validDeclarationStoreRequest().Attribution,
		KeyDigest: testDigest, RequestDigest: testDigest,
	}
	return CredentialLifecycleApplyRequest{Binding: binding, Stage: stage}
}

func TestCredentialLifecycleCannotAppendWithoutExactHumanRun(t *testing.T) {
	repository := openCredentialStore(t)
	request := lifecycleStageRequest(lifecycleStageBinding())
	if _, err := repository.ApplyCredentialLifecycle(context.Background(), request); Code(err) != generated.ErrorCodePrerequisiteBlocked {
		t.Fatalf("lifecycle append bypassed the exact plan: %v", err)
	}
	for _, table := range []string{"credential_reference_versions", "credential_consumer_verifications", "credential_recovery_records"} {
		var count int
		if err := repository.store.conn.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM "+table).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("table %s changed on a blocked append: %d", table, count)
		}
	}
}

func TestCredentialLifecycleTablesAreAppendOnly(t *testing.T) {
	repository := openCredentialStore(t)
	for _, table := range []string{"credential_lifecycle_bindings", "credential_consumer_verifications", "credential_recovery_records"} {
		var count int
		if err := repository.store.conn.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM sqlite_master WHERE type='trigger' AND tbl_name=?", table).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 2 {
			t.Fatalf("append-only triggers missing for %s: %d", table, count)
		}
	}
}

func TestCredentialLifecycleRejectsForgedActionNullables(t *testing.T) {
	repository := openCredentialStore(t)
	// A stage binding must not carry recovery custody proof.
	binding := lifecycleStageBinding()
	binding.CustodyProofDigest = stringPointer(testDigest)
	request := lifecycleStageRequest(binding)
	request.Binding = binding
	if _, err := repository.ApplyCredentialLifecycle(context.Background(), request); Code(err) != generated.ErrorCodeInputInvalid {
		t.Fatalf("forged stage binding admitted: %v", err)
	}
	// A recover binding with a non-increasing epoch must be rejected.
	recover := lifecycleStageBinding()
	recover.Action = credentialref.ActionRecover
	recover.PriorRecoveryEpoch = int64PointerLifecycle(0)
	recover.RecoveryEpoch = 0
	recover.CustodyProofDigest = stringPointer(testDigest)
	recover.FormerControllerFenceDigest = stringPointer(testDigest)
	recoverRequest := lifecycleStageRequest(recover)
	recoverRequest.Binding = recover
	if _, err := repository.ApplyCredentialLifecycle(context.Background(), recoverRequest); Code(err) != generated.ErrorCodeInputInvalid {
		t.Fatalf("non-increasing recover epoch admitted: %v", err)
	}
}

func int64PointerLifecycle(value int64) *int64 { return &value }
