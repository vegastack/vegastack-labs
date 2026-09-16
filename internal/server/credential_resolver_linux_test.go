//go:build linux

package server

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/adapter/onepassword"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type fakeAppliedCredentialProfile struct{ scope store.GateAppliedProfile }

func (fake fakeAppliedCredentialProfile) GetAppliedProfileScope(context.Context) (store.GateAppliedProfile, error) {
	return fake.scope, nil
}

type fakeCredentialRevision struct{ current store.RevisionToken }

func (fake fakeCredentialRevision) CurrentRevision(context.Context) (store.RevisionToken, error) {
	return fake.current, nil
}

type fakeOnePasswordRead struct{}

func (fakeOnePasswordRead) Resolve(context.Context, string) (string, error) {
	return "synthetic-private-canary", nil
}

func TestOptionalOnePasswordCompositionReadsTokenOnlyFromNativeServiceCredential(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "op-service-token"), []byte("synthetic-service-account-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CREDENTIALS_DIRECTORY", dir)
	registry := adapter.NewRegistry()
	scope := adapter.CredentialCapabilityScope{ResolverID: "onepassword-a", ConsumerID: "adapter-a", ProfileID: "profile-a", CapabilityID: "credential.onepassword.read", Enabled: true}
	config := onepassword.Config{IDs: onepassword.IDs{VaultID: "vault-id", ItemID: "item-id", FieldID: "field-id"}, ReferenceID: "ref-a", ConsumerID: "adapter-a", PurposeID: "deploy-a", TargetID: "service-a", MaterialVersion: "version-a", ResolverID: "onepassword-a", AllowedVaultIDs: []string{"vault-id"}}
	profile := fakeAppliedCredentialProfile{store.GateAppliedProfile{ProfileID: "profile-a", Capabilities: []string{"credential.onepassword.read"}, StateRevision: 1, RecoveryEpoch: 0}}
	revisions := fakeCredentialRevision{store.RevisionToken{StateRevision: 1, RecoveryEpoch: 0}}
	if err := composeOptionalOnePasswordCredential(context.Background(), uint32(os.Geteuid()), "op-service-token", registry, scope, config, profile, revisions, fakeOnePasswordRead{}); err != nil {
		t.Fatal(err)
	}
	resolved, err := registry.ResolveCredentialResolver(scope.ResolverID, scope.ConsumerID, scope.ProfileID)
	if err != nil {
		t.Fatal(err)
	}
	binding := credentialref.StepBinding{OperationID: "operation-a", AdapterID: "adapter-a", TargetID: "service-a", ReferenceID: "ref-a", ConsumerID: "adapter-a", PurposeID: "deploy-a", MaterialVersion: "version-a", ResolverID: "onepassword-a", StateRevision: 3, RecoveryEpoch: 0}
	value, err := resolved.Resolve(context.Background(), binding)
	if err != nil {
		t.Fatal(err)
	}
	value.Close()
	denied := profile
	denied.scope.Capabilities = nil
	if err := composeOptionalOnePasswordCredential(context.Background(), uint32(os.Geteuid()), "missing-token", adapter.NewRegistry(), scope, config, denied, revisions, fakeOnePasswordRead{}); err == nil {
		t.Fatal("unapproved capability consumed token")
	}
}
