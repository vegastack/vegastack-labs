package server

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"strings"
	"testing"
)

type actionConsoleFixture struct {
	calls int
	err   error
}

func (f *actionConsoleFixture) VerifyHostActionConsole(context.Context, string, generated.HostActionCredentialConfirmation, int64) error {
	f.calls++
	return f.err
}

type actionLifecycleFixture struct {
	binding   credentialref.LifecycleBinding
	reference generated.CredentialReference
}

func (f actionLifecycleFixture) GetLifecycleBinding(context.Context, generated.Plan, string) (credentialref.LifecycleBinding, error) {
	return f.binding, nil
}

type actionFallbackFixture struct{ calls int }

func (f *actionFallbackFixture) VerifySecretStep(context.Context, generated.Plan, generated.PlanOperation) error {
	f.calls++
	return actionFailure()
}
func TestHostActionGateExactScopeAndFallback(t *testing.T) {
	digest := hostaction.Digest("synthetic identity")
	r := generated.HostActionRequest{Schema: generated.SchemaIDHostActionRequest, SchemaVersion: "1.0.0", ActionID: "test.write-file", ActionVersion: "1.0.0", ActionInput: "{}", ActionInputDigest: hostaction.BytesDigest([]byte("{}")), HostID: "host-a", TargetRevision: 1, TargetDigest: digest, AutomationPrincipalID: "service-a", CallerUID: 1001, CredentialReferenceID: "key-a", CredentialMaterialVersion: "version-a", ConsoleConfirmation: generated.HostActionConsoleConfirmation{Schema: generated.SchemaIDHostActionConsoleConfirmation, SchemaVersion: "1.0.0", Method: "administrator-verified-console", TargetDigest: digest, HostIdentityDigest: digest}, ExpectedStateRevision: 1, IdempotencyKey: "action-a"}
	op := generated.PlanOperation{OperationID: "action-a", OperationType: hostaction.OperationType, AdapterID: hostaction.AdapterID, TargetID: r.HostID, ArtifactDigest: hostaction.Digest(r)}
	p := generated.Plan{HostAction: &r, AuthorizationBranch: "human", ExecutorMode: "central", Operations: []generated.PlanOperation{op}}
	source := &actionConsoleFixture{}
	fallback := &actionFallbackFixture{}
	g := hostActionGate{targets: source, allowed: []string{digest}, fallback: fallback}
	if err := g.VerifySecretStep(context.Background(), p, op); err != nil || source.calls != 1 || fallback.calls != 0 {
		t.Fatalf("exact action: %v", err)
	}
	for _, change := range []func(*generated.Plan, *hostActionGate){func(_ *generated.Plan, g *hostActionGate) { g.allowed = nil }, func(p *generated.Plan, _ *hostActionGate) { p.AuthorizationBranch = "preauthorized" }, func(p *generated.Plan, _ *hostActionGate) { p.HostAction = nil }, func(p *generated.Plan, _ *hostActionGate) { p.Operations = nil }} {
		pp, gg := p, g
		change(&pp, &gg)
		before := source.calls
		if err := gg.VerifySecretStep(context.Background(), pp, op); err == nil || source.calls != before {
			t.Fatal("unbound action reached console source")
		}
	}
	unrelated := generated.PlanOperation{OperationType: "credential.recover", AdapterID: "core.credentials"}
	if g.VerifySecretStep(context.Background(), p, unrelated) == nil || fallback.calls != 1 {
		t.Fatal("existing recovery fallback bypassed")
	}
	g.fallback = nil
	if g.VerifySecretStep(context.Background(), p, unrelated) == nil {
		t.Fatal("nil fallback passed")
	}
}
func TestHostActionTargetsRequireExactInstallationIdentity(t *testing.T) {
	s := hostActionTargets{allowed: []string{hostaction.Digest("approved physical identity")}}
	if _, err := s.Resolve(context.Background(), generated.HostActionBundle{HostIdentityDigest: hostaction.Digest("alias of another physical identity")}); err == nil {
		t.Fatal("unknown physical identity accepted")
	}
}

func (f actionLifecycleFixture) GetCredentialVersion(context.Context, string, string) (generated.CredentialReference, error) {
	return f.reference, nil
}

func TestHostActionLifecycleGateRequiresExactConsumerReference(t *testing.T) {
	d := hostaction.Digest("synthetic metadata")
	b := credentialref.LifecycleBinding{OperationID: "activate-a", Action: credentialref.ActionActivate, ReferenceID: "key-a", MaterialVersion: "version-a", ResolverID: "native-systemd", TargetID: "host-a", CiphertextFingerprint: d, StateRevision: 1, ConsumerIDs: []string{hostaction.AdapterID}, RequiredDeniedConsumerIDs: []string{"denied-a"}, NativeArtifactConsumerID: hostaction.AdapterID, HostActionConsole: &credentialref.HostActionConsoleBinding{Method: "administrator-verified-console", TargetDigest: d, HostIdentityDigest: d, TargetRevision: 1}}
	b.NativeConsumers = []credentialref.NativeConsumerBinding{{ConsumerID: hostaction.AdapterID, TargetID: b.TargetID, HostMachineID: strings.Repeat("a", 32), UnitName: "synthetic.service", ServiceUID: 1001, ServiceGID: 1001, ProfileID: "profile-a", RoleID: "role-a", LoadedName: credentialref.LoadedNameForVersion(hostaction.AdapterID, b.ReferenceID, b.MaterialVersion)}}
	b.NativeDeniedReaders = []credentialref.NativeDeniedReaderBinding{{ConsumerID: "denied-a", TargetID: b.TargetID, HostMachineID: strings.Repeat("a", 32), ReaderUID: 1002, ReaderGID: 1002, ProfileID: "profile-a", RoleID: "role-denied"}}
	if !credentialref.ValidLifecycleBinding(b) {
		t.Fatal("invalid synthetic lifecycle fixture")
	}
	op := generated.PlanOperation{OperationID: b.OperationID, OperationType: string(b.Action), TargetID: b.TargetID}
	p := generated.Plan{AuthorizationBranch: "human", ExecutorMode: "central", Operations: []generated.PlanOperation{op}, HostActionConsole: &generated.HostActionCredentialConfirmation{Method: b.HostActionConsole.Method, TargetDigest: d, HostIdentityDigest: d, TargetRevision: 1}}
	ref := generated.CredentialReference{ReferenceID: b.ReferenceID, ConsumerID: hostaction.AdapterID, PurposeID: hostaction.PurposeID, TargetID: b.TargetID, ResolverID: b.ResolverID, MaterialVersion: b.MaterialVersion}
	source := &actionConsoleFixture{}
	g := hostActionGate{targets: source, credentials: actionLifecycleFixture{binding: b, reference: ref}, allowed: []string{d}}
	if err := g.VerifySecretStep(context.Background(), p, op); err != nil {
		t.Fatal(err)
	}
	ref.PurposeID = "unrelated-purpose"
	g.credentials = actionLifecycleFixture{binding: b, reference: ref}
	if err := g.VerifySecretStep(context.Background(), p, op); err == nil {
		t.Fatal("unrelated reference qualified")
	}
	p.HostActionConsole.TargetRevision++
	if err := g.VerifySecretStep(context.Background(), p, op); err == nil {
		t.Fatal("changed console accepted")
	}
}
