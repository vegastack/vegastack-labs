package server

import (
	"context"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/ingressconnector"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/store"
	"strings"
	"testing"
)

func TestIngressConnectorGateRejectsUnselectedScopeAndMissingBaseline(t *testing.T) {
	d := "sha256:" + strings.Repeat("a", 64)
	in := ingressconnector.Input{HostID: "synthetic-controller", AccountID: strings.Repeat("a", 32), HostIdentityDigest: d, TunnelID: "11111111-1111-1111-1111-111111111111"}
	raw, _ := json.Marshal(in)
	base := generated.Plan{AuthorizationBranch: "human", ExecutorMode: "central", Binding: generated.PlanBinding{StateRevision: 7, RecoveryEpoch: 2}, HostAction: &generated.HostActionRequest{ActionID: ingressconnector.Action, ActionVersion: "1.0.0", HostID: in.HostID, ActionInput: string(raw), ConsoleConfirmation: generated.HostActionConsoleConfirmation{HostIdentityDigest: d}}, Operations: []generated.PlanOperation{{AdapterID: hostaction.AdapterID, OperationType: hostaction.OperationType}}}
	selected := connectorSelection{HostID: in.HostID, AccountID: in.AccountID, IdentityDigest: d, TunnelID: in.TunnelID, RecoveryEpoch: 2}
	baseline := func(context.Context, string) (store.HostAdmissionSnapshot, error) {
		return store.HostAdmissionSnapshot{Host: generated.ManagedHost{HostID: in.HostID}, IdentityDigest: d, Revision: store.RevisionToken{StateRevision: 7, RecoveryEpoch: 2}}, nil
	}
	if e := verifyIngressConnector(context.Background(), base, selected, baseline, nil); e != nil {
		t.Fatal("exact selection", e)
	}
	for _, fault := range []string{"no-baseline", "baseline-denied", "account", "host", "identity", "tunnel", "epoch", "ca", "unconfigured", "nonhuman", "mixed", "idempotent", "baseline-stale"} {
		t.Run(fault, func(t *testing.T) {
			p := base
			p.Operations = append([]generated.PlanOperation{}, base.Operations...)
			s := selected
			b := connectorBaseline(baseline)
			switch fault {
			case "no-baseline":
				b = nil
			case "baseline-denied":
				b = func(context.Context, string) (store.HostAdmissionSnapshot, error) {
					return store.HostAdmissionSnapshot{}, actionFailure()
				}
			case "account":
				s.AccountID = strings.Repeat("b", 32)
			case "host":
				s.HostID = "other"
			case "identity":
				s.IdentityDigest = "sha256:" + strings.Repeat("b", 64)
			case "tunnel":
				s.TunnelID = "22222222-2222-2222-2222-222222222222"
			case "epoch":
				s.RecoveryEpoch++
			case "ca":
				s.OriginCAPool = ingressconnector.CAPath
			case "unconfigured":
				s.TunnelID = ""
			case "nonhuman":
				p.AuthorizationBranch = "preauthorized"
			case "mixed":
				p.Operations = append(p.Operations, p.Operations[0])
			case "idempotent":
				p.Operations[0].Idempotent = true
			case "baseline-stale":
				b = func(c context.Context, h string) (store.HostAdmissionSnapshot, error) {
					v, e := baseline(c, h)
					v.Revision.StateRevision--
					return v, e
				}
			}
			if e := verifyIngressConnector(context.Background(), p, s, b, nil); e == nil {
				t.Fatal("unqualified scope accepted")
			}
		})
	}
}

func TestConnectorActionCannotInheritOrdinaryHostGateWithoutScope(t *testing.T) {
	d := hostaction.Digest("synthetic controller")
	in := ingressconnector.Input{HostID: "host-a", AccountID: strings.Repeat("a", 32), HostIdentityDigest: d, TunnelID: "11111111-1111-1111-1111-111111111111"}
	raw, _ := json.Marshal(in)
	r := generated.HostActionRequest{Schema: generated.SchemaIDHostActionRequest, SchemaVersion: "1.0.0", ActionID: ingressconnector.Action, ActionVersion: "1.0.0", ActionInput: string(raw), ActionInputDigest: hostaction.BytesDigest(raw), HostID: in.HostID, TargetRevision: 1, TargetDigest: d, AutomationPrincipalID: "service-a", CallerUID: 1001, CredentialReferenceID: "key-a", CredentialMaterialVersion: "v1", ConsoleConfirmation: generated.HostActionConsoleConfirmation{Schema: generated.SchemaIDHostActionConsoleConfirmation, SchemaVersion: "1.0.0", Method: "administrator-verified-console", TargetDigest: d, HostIdentityDigest: d}, ExpectedStateRevision: 1, IdempotencyKey: "connector-one"}
	op := generated.PlanOperation{OperationID: "connector-one", OperationType: hostaction.OperationType, AdapterID: hostaction.AdapterID, TargetID: r.HostID, ArtifactDigest: hostaction.Digest(r)}
	p := generated.Plan{HostAction: &r, AuthorizationBranch: "human", ExecutorMode: "central", Operations: []generated.PlanOperation{op}}
	source := &actionConsoleFixture{}
	g := hostActionGate{targets: source, allowed: []string{d}}
	if e := g.VerifySecretStep(context.Background(), p, op); e == nil || source.calls != 0 {
		t.Fatal("missing connector selection inherited ordinary action authority")
	}
	calls := 0
	g.connector = func(context.Context, generated.Plan) error { calls++; return actionFailure() }
	if e := g.VerifySecretStep(context.Background(), p, op); e == nil || calls != 1 || source.calls != 0 {
		t.Fatal("scope/baseline rejection bypassed")
	}
	g.connector = func(context.Context, generated.Plan) error { calls++; return nil }
	if e := g.VerifySecretStep(context.Background(), p, op); e != nil || calls != 2 || source.calls != 1 {
		t.Fatal("current target confirmation skipped", e, calls, source.calls)
	}
	if e := ingressConnectorAuthorization(serverconfig.Profile{}, nil, nil, nil)(context.Background(), p); e == nil {
		t.Fatal("unconfigured production source accepted")
	}
}

func TestConnectorPilotMarkerUsesOnlySharedActualEligibility(t *testing.T) {
	d := hostaction.Digest("identity")
	marker := hostaction.Digest("approved complete policy")
	in := ingressconnector.Input{HostID: "host-a", AccountID: strings.Repeat("a", 32), HostIdentityDigest: d, TunnelID: "11111111-1111-1111-1111-111111111111", ControllerSetupPilotDigest: marker}
	raw, _ := json.Marshal(in)
	p := generated.Plan{AuthorizationBranch: "human", ExecutorMode: "central", Binding: generated.PlanBinding{StateRevision: 4, RecoveryEpoch: 2}, HostAction: &generated.HostActionRequest{ActionID: ingressconnector.Action, ActionVersion: "1.0.0", HostID: in.HostID, ActionInput: string(raw), ConsoleConfirmation: generated.HostActionConsoleConfirmation{HostIdentityDigest: d}}, Operations: []generated.PlanOperation{{AdapterID: hostaction.AdapterID, OperationType: hostaction.OperationType}}}
	selected := connectorSelection{HostID: in.HostID, IdentityDigest: d, AccountID: in.AccountID, TunnelID: in.TunnelID, RecoveryEpoch: 2}
	baselineCalls, pilotCalls := 0, 0
	baseline := func(context.Context, string) (store.HostAdmissionSnapshot, error) {
		baselineCalls++
		return store.HostAdmissionSnapshot{}, actionFailure()
	}
	pilot := func(_ context.Context, plan generated.Plan) (store.HostAdmissionSnapshot, error) {
		pilotCalls++
		actual, e := ingressconnector.Decode([]byte(plan.HostAction.ActionInput))
		if e != nil || actual.ControllerSetupPilotDigest != marker {
			return store.HostAdmissionSnapshot{}, actionFailure()
		}
		return store.HostAdmissionSnapshot{Host: generated.ManagedHost{HostID: in.HostID}, IdentityDigest: d, Revision: store.RevisionToken{StateRevision: 4, RecoveryEpoch: 2}}, nil
	}
	if e := verifyIngressConnector(context.Background(), p, selected, baseline, nil); e == nil {
		t.Fatal("marker alone became eligibility")
	}
	if e := verifyIngressConnector(context.Background(), p, selected, baseline, pilot); e != nil || baselineCalls != 0 || pilotCalls != 1 {
		t.Fatal("wrong shared eligibility dispatch", e, baselineCalls, pilotCalls)
	}
	in.ControllerSetupPilotDigest = hostaction.Digest("different policy")
	raw, _ = json.Marshal(in)
	p.HostAction.ActionInput = string(raw)
	if e := verifyIngressConnector(context.Background(), p, selected, baseline, pilot); e == nil {
		t.Fatal("mismatched policy accepted")
	}
	in.ControllerSetupPilotDigest = ""
	raw, _ = json.Marshal(in)
	p.HostAction.ActionInput = string(raw)
	if e := verifyIngressConnector(context.Background(), p, selected, baseline, pilot); e == nil || baselineCalls != 1 || pilotCalls != 2 {
		t.Fatal("unmarked plan bypassed ordinary baseline", e, baselineCalls, pilotCalls)
	}
}
