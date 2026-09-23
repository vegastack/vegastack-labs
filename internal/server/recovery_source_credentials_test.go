package server

import (
	"context"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/adapter/localbackup"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type recoveryReferenceStub struct{ reference generated.CredentialReference }

func (stub recoveryReferenceStub) GetActiveVersion(context.Context, string, int64) (generated.CredentialReference, error) {
	return stub.reference, nil
}

type recoveryProfileStub struct{ profile store.GateAppliedProfile }

func (stub recoveryProfileStub) GetAppliedProfileScope(context.Context) (store.GateAppliedProfile, error) {
	return stub.profile, nil
}

type recoveryRevisionStub struct{ revision store.RevisionToken }

func (stub recoveryRevisionStub) CurrentRevision(context.Context) (store.RevisionToken, error) {
	return stub.revision, nil
}

type recoveryResolverStub struct{ value []byte }

func (stub recoveryResolverStub) Resolve(context.Context, credentialref.StepBinding) (*credentialref.Value, error) {
	return credentialref.NewValue(stub.value)
}

type recoveryResolverRegistryStub struct{ capability string }

func (stub recoveryResolverRegistryStub) ResolveCredentialCapability(string, string, string) (string, error) {
	return stub.capability, nil
}
func (stub recoveryResolverRegistryStub) ResolveCredentialResolver(string, string, string) (adapter.CredentialResolver, error) {
	return recoveryResolverStub{value: []byte("synthetic-private-recovery-key")}, nil
}

func TestRecoveryCredentialBorrowerRequiresCurrentReferenceAndCapability(t *testing.T) {
	activated := "2026-09-24T00:00:00Z"
	reference := generated.CredentialReference{ReferenceID: "backup-key", ConsumerID: localbackup.AdapterID, PurposeID: "backup-encryption", TargetID: "repository-critical", ResolverID: "native-systemd", MaterialVersion: "version-a", Status: "active", StateRevision: 8, RecoveryEpoch: 3, ActivatedAt: &activated, VerifiedConsumerIDs: []string{localbackup.AdapterID}}
	request := localbackup.RecoveryCredentialRequest{ReferenceID: reference.ReferenceID, ConsumerID: localbackup.AdapterID, PlanID: "restore-preflight", PlanDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", RunID: "preflight-run", StepID: "preflight-step", LeaseID: "preflight-lease", StateRevision: 8, RecoveryEpoch: 3}
	borrower := recoveryCredentialBorrower{references: recoveryReferenceStub{reference}, profiles: recoveryProfileStub{store.GateAppliedProfile{ProfileID: "profile-a", Capabilities: []string{"credential.backup.read"}, StateRevision: 8, RecoveryEpoch: 3}}, revisions: recoveryRevisionStub{store.RevisionToken{StateRevision: 8, RecoveryEpoch: 3}}, resolvers: recoveryResolverRegistryStub{capability: "credential.backup.read"}}
	value, err := borrower.BorrowRecoveryCredential(context.Background(), request)
	if err != nil || value == nil || len(value.Bytes()) == 0 {
		t.Fatalf("borrow = (%v, %v)", value, err)
	}
	value.Close()

	borrower.profiles = recoveryProfileStub{store.GateAppliedProfile{ProfileID: "profile-a", StateRevision: 8, RecoveryEpoch: 3}}
	if value, err := borrower.BorrowRecoveryCredential(context.Background(), request); err == nil || value != nil {
		t.Fatalf("missing capability borrow = (%v, %v)", value, err)
	}
}
