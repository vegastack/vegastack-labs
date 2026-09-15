package onepassword

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
)

type fakeSecretsAPI struct {
	calls    int
	uri      string
	response string
	failure  error
}

func (api *fakeSecretsAPI) Resolve(_ context.Context, uri string) (string, error) {
	api.calls++
	api.uri = uri
	return api.response, api.failure
}

func testBinding() credentialref.StepBinding {
	return credentialref.StepBinding{OperationID: "operation-a", AdapterID: "adapter-a", TargetID: "service-a", ReferenceID: "ref-a", ConsumerID: "adapter-a", PurposeID: "deploy-a", MaterialVersion: "version-a", ResolverID: "onepassword-a", StateRevision: 3, RecoveryEpoch: 0}
}

func TestOnePasswordResolverUsesOnlyExactIDsAndOneRead(t *testing.T) {
	api := &fakeSecretsAPI{response: "synthetic-private-canary"}
	token, err := credentialref.NewValue([]byte("synthetic-service-account-token"))
	if err != nil {
		t.Fatal(err)
	}
	alias := token.Bytes()
	config := Config{IDs: IDs{VaultID: "vault-id", ItemID: "item-id", FieldID: "field-id"}, ReferenceID: "ref-a", ConsumerID: "adapter-a", PurposeID: "deploy-a", TargetID: "service-a", MaterialVersion: "version-a", ResolverID: "onepassword-a", AllowedVaultIDs: []string{"vault-id"}}
	resolver, err := NewResolver(context.Background(), token, config, api)
	if err != nil {
		t.Fatal(err)
	}
	for _, byteValue := range alias {
		if byteValue != 0 {
			t.Fatal("app-owned token not wiped after resolver creation")
		}
	}
	value, err := resolver.Resolve(context.Background(), testBinding())
	if err != nil {
		t.Fatal(err)
	}
	defer value.Close()
	if api.calls != 1 || api.uri != "op://vault-id/item-id/field-id" {
		t.Fatalf("lookup widened: calls=%d uri=%s", api.calls, api.uri)
	}
	cross := testBinding()
	cross.ConsumerID = "other-consumer"
	if _, err := resolver.Resolve(context.Background(), cross); err == nil || api.calls != 1 {
		t.Fatal("cross-consumer lookup not denied before SDK")
	}
	deniedConfig := config
	deniedConfig.AllowedVaultIDs = []string{"other-vault"}
	deniedToken, _ := credentialref.NewValue([]byte("synthetic-service-account-token"))
	if _, err := NewResolver(context.Background(), deniedToken, deniedConfig, api); err == nil {
		t.Fatal("denied vault accepted")
	}
}

func TestOnePasswordSDKErrorAndValueStayOutOfErrorSurface(t *testing.T) {
	api := &fakeSecretsAPI{failure: errors.New("synthetic-private-canary"), response: ""}
	token, _ := credentialref.NewValue([]byte("synthetic-service-account-token"))
	config := Config{IDs: IDs{VaultID: "vault-id", ItemID: "item-id", FieldID: "field-id"}, ReferenceID: "ref-a", ConsumerID: "adapter-a", PurposeID: "deploy-a", TargetID: "service-a", MaterialVersion: "version-a", ResolverID: "onepassword-a", AllowedVaultIDs: []string{"vault-id"}}
	resolver, err := NewResolver(context.Background(), token, config, api)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.Resolve(context.Background(), testBinding()); err == nil || strings.Contains(err.Error(), "synthetic-private-canary") {
		t.Fatalf("SDK error escaped: %v", err)
	}
	api.failure = nil
	api.response = strings.Repeat("x", 4097)
	if _, err := resolver.Resolve(context.Background(), testBinding()); err == nil {
		t.Fatal("oversize value accepted")
	}
}

func TestParseIDsRejectsPathsWildcardsAndNames(t *testing.T) {
	for _, raw := range []string{"../vault", "vault/name", "vault?query", "vault%2fid", "*", "Vault With Spaces", ""} {
		if _, err := ParseIDs(raw, "item-id", "field-id"); err == nil {
			t.Fatalf("non-exact vault ID accepted: %s", raw)
		}
	}
}
