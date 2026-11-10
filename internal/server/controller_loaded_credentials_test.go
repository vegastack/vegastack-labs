package server

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/store"
)

func controllerCredentialFixture() (serverconfig.Profile, store.GateAppliedProfile, credentialref.LifecycleBinding, generated.CredentialReference) {
	consumer, refID, target := "registry.harbor", "registry-observer", "manual-demo"
	d, machine := hostaction.Digest("synthetic ciphertext"), strings.Repeat("a", 32)
	b := credentialref.LifecycleBinding{OperationID: "activate-a", Action: credentialref.ActionActivate, ReferenceID: refID, MaterialVersion: "initial", ResolverID: "native-systemd", TargetID: target, CiphertextFingerprint: d, StateRevision: 2, ConsumerIDs: []string{consumer}, RequiredDeniedConsumerIDs: []string{"denied-a"}, NativeArtifactConsumerID: consumer}
	b.NativeConsumers = []credentialref.NativeConsumerBinding{{ConsumerID: consumer, TargetID: target, HostMachineID: machine, UnitName: "vsk-labs.service", ServiceUID: 1001, ServiceGID: 1001, ProfileID: "profile-a", RoleID: "control", LoadedName: credentialref.LoadedNameForVersion(consumer, refID, "initial")}}
	b.NativeDeniedReaders = []credentialref.NativeDeniedReaderBinding{{ConsumerID: "denied-a", TargetID: target, HostMachineID: machine, ReaderUID: 1002, ReaderGID: 1002, ProfileID: "profile-a", RoleID: "control"}}
	ref := generated.CredentialReference{ReferenceID: refID, ConsumerID: consumer, PurposeID: "registry-observe", TargetID: target, ResolverID: "native-systemd", MaterialVersion: "initial", Status: "staged", Fingerprint: d}
	p := serverconfig.Profile{SocketOwnerUID: 1001, ServiceBindings: []generated.ServiceProviderBinding{{ServiceID: target, Harbor: &generated.HarborServiceBinding{ObservationReferenceID: refID}}}}
	scope := store.GateAppliedProfile{ProfileID: "profile-a", StateRevision: 1, Capabilities: []string{"credential.registry.read"}}
	return p, scope, b, ref
}

func TestDeclaredControllerCredentialGate(t *testing.T) {
	for _, fault := range []string{"none", "reference", "target", "consumer", "unit", "purpose", "profile", "missing-denied", "missing-declaration", "capability", "nonhuman"} {
		t.Run(fault, func(t *testing.T) {
			config, scope, b, ref := controllerCredentialFixture()
			switch fault {
			case "reference":
				ref.ReferenceID = "elsewhere"
			case "target":
				ref.TargetID = "elsewhere"
			case "consumer":
				ref.ConsumerID = "elsewhere"
			case "unit":
				b.NativeConsumers[0].UnitName = "another.service"
			case "purpose":
				ref.PurposeID = "registry-push"
			case "profile":
				b.NativeConsumers[0].ProfileID = "other-profile"
			case "missing-denied":
				b.NativeDeniedReaders = nil
				b.RequiredDeniedConsumerIDs = nil
			case "missing-declaration":
				config.ServiceBindings = nil
			case "capability":
				scope.Capabilities = nil
			}
			op := generated.PlanOperation{OperationID: b.OperationID, OperationType: string(b.Action), TargetID: b.TargetID}
			plan := generated.Plan{AuthorizationBranch: "human", ExecutorMode: "central", Operations: []generated.PlanOperation{op}}
			if fault == "nonhuman" {
				plan.AuthorizationBranch = "preauthorized"
			}
			gate := hostActionGate{credentials: actionLifecycleFixture{binding: b, reference: ref}, fallback: &actionFallbackFixture{}, loadedCredential: func(ctx context.Context, b credentialref.LifecycleBinding) bool {
				cap := declaredControllerCredentialCapability(ctx, config, scope, b, ref)
				return cap != "" && slices.Contains(scope.Capabilities, cap)
			}}
			err := gate.VerifySecretStep(context.Background(), plan, op)
			if (fault == "none") != (err == nil) {
				t.Fatalf("gate result %v", err)
			}
		})
	}
}

func TestControllerHarborHostingConfigurationIsDigestBound(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("protected configuration reader is Linux-only")
	}
	p, scope, b, ref := controllerCredentialFixture()
	p.SocketOwnerUID = uint32(os.Getuid())
	b.NativeConsumers[0].ServiceUID = p.SocketOwnerUID
	b.ConsumerIDs = []string{"registry.harbor.manage"}
	b.NativeArtifactConsumerID = b.ConsumerIDs[0]
	b.NativeConsumers[0].ConsumerID = b.ConsumerIDs[0]
	b.NativeConsumers[0].LoadedName = credentialref.LoadedNameForVersion(b.ConsumerIDs[0], b.ReferenceID, b.MaterialVersion)
	ref.ConsumerID = b.ConsumerIDs[0]
	ref.PurposeID = "registry-manage"
	p.ServiceBindings = nil
	raw, _ := json.Marshal(hostingConfiguration{Harbor: &hostingHarbor{ReferenceID: b.ReferenceID}})
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "hosting.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if !credentialref.ValidLifecycleBinding(b) {
		t.Fatal("invalid synthetic lifecycle")
	}
	if _, err := readLocalSetupProtected(context.Background(), path, p.SocketOwnerUID, 1<<20); err != nil {
		t.Fatalf("invalid protected fixture: %v", err)
	}
	p.HostingLifecycleProfiles = []generated.HostingLifecycleProfile{{TargetID: b.TargetID, ConfigurationPath: path, ConfigurationDigest: hostaction.BytesDigest(raw)}}
	if got := declaredControllerCredentialCapability(context.Background(), p, scope, b, ref); got != "credential.registry.manage" {
		t.Fatalf("configured Harbor activation refused: %q", got)
	}
	if err := os.WriteFile(path, []byte(`{"harbor":{"referenceId":"different"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if got := declaredControllerCredentialCapability(context.Background(), p, scope, b, ref); got != "" {
		t.Fatal("changed protected configuration accepted")
	}
}
