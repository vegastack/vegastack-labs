package server

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostdiscovery"
	"github.com/vegastack/vegastack-labs/internal/store"
	"testing"
)

type discoveryVerifierStub struct {
	deny  bool
	calls int
}

func (v *discoveryVerifierStub) CheckCollection(context.Context, hostdiscovery.Target) error {
	v.calls++
	if v.deny {
		return hostdiscovery.Error(generated.ErrorCodeAuthorizationDenied)
	}
	return nil
}

type discoveryResolverStub struct {
	calls   int
	binding credentialref.StepBinding
	value   *credentialref.Value
}

func (r *discoveryResolverStub) Resolve(_ context.Context, b credentialref.StepBinding) (*credentialref.Value, error) {
	r.calls++
	r.binding = b
	r.value, _ = credentialref.NewValue([]byte("synthetic-key-material"))
	return r.value, nil
}
func TestHostDiscoveryCredentialBinding(t *testing.T) {
	for _, mode := range []string{"valid", "target", "purpose", "consumer", "version", "epoch", "revoked", "unqualified", "grant"} {
		t.Run(mode, func(t *testing.T) {
			active := "2026-10-07T00:00:00Z"
			ref := generated.CredentialReference{ReferenceID: "ref-a", ConsumerID: hostdiscovery.Consumer, PurposeID: hostdiscovery.Purpose, TargetID: "candidate-a", ResolverID: "native-systemd", MaterialVersion: "version-a", Status: "active", ActivatedAt: &active, StateRevision: 1, VerifiedConsumerIDs: []string{hostdiscovery.Consumer}}
			target := hostdiscovery.Target{Binding: generated.HostDiscoveryTarget{TargetID: "candidate-a", ProfileID: "profile-a", CredentialReferenceID: "ref-a", MaterialVersion: "version-a"}, StateRevision: 2, GrantRevision: 1}
			verifier := &discoveryVerifierStub{}
			resolver := &discoveryResolverStub{}
			registry := adapter.NewRegistry()
			if err := registry.RegisterCredentialResolver(adapter.CredentialCapabilityScope{ResolverID: "native-systemd", ConsumerID: hostdiscovery.Consumer, ProfileID: "profile-a", CapabilityID: "credential.discovery.read", Enabled: true}, resolver); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "target":
				ref.TargetID = "other"
			case "purpose":
				ref.PurposeID = "other"
			case "consumer":
				ref.ConsumerID = "other"
			case "version":
				ref.MaterialVersion = "other"
			case "epoch":
				ref.RecoveryEpoch = 1
			case "revoked":
				ref.Status = "revoked"
			case "unqualified":
				ref.VerifiedConsumerIDs = nil
			case "grant":
				verifier.deny = true
			}
			borrower := hostDiscoveryCredentials{targets: verifier, references: recoveryReferenceStub{reference: ref}, profiles: recoveryProfileStub{profile: store.GateAppliedProfile{ProfileID: "profile-a", Capabilities: []string{"credential.discovery.read"}}}, resolvers: registry}
			value, err := borrower.Borrow(context.Background(), target)
			if mode == "valid" {
				if err != nil || value == nil {
					t.Fatal(err)
				}
				value.Close()
				if resolver.binding.TargetID != target.Binding.TargetID || resolver.binding.ConsumerID != hostdiscovery.Consumer {
					t.Fatal("wrong credential binding")
				}
			} else if err == nil || value != nil || resolver.calls != 0 {
				t.Fatalf("invalid binding resolved a credential: %s", mode)
			}
		})
	}
}
