package ingressconnector

import (
	"context"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"strings"
	"testing"
)

type fixtureRuntime struct {
	calls  int
	result Result
	err    error
}

func (r *fixtureRuntime) Install(context.Context, Input) (Result, error) {
	r.calls++
	return r.result, r.err
}
func fixtureInput() Input {
	return Input{HostID: "synthetic-controller", AccountID: strings.Repeat("a", 32), HostIdentityDigest: "sha256:" + strings.Repeat("a", 64), TunnelID: "11111111-1111-1111-1111-111111111111"}
}
func fixtureBundle(in Input) generated.HostActionBundle {
	raw, _ := json.Marshal(in)
	d := "sha256:" + strings.Repeat("b", 64)
	return generated.HostActionBundle{Schema: generated.SchemaIDHostActionBundle, SchemaVersion: "1.0.0", ActionID: Action, ActionVersion: "1.0.0", ActionInput: string(raw), ActionInputDigest: hostaction.BytesDigest(raw), BundleID: "bundle-one", PlanID: "plan-one", PlanDigest: d, RunID: "run-one", StepID: "step-one", LeaseID: "lease-one", HostID: in.HostID, HostIdentityDigest: in.HostIdentityDigest, ConsoleConfirmationDigest: d, DeclarationID: "declaration-one", DeclarationRevision: 1, AutomationPrincipalID: "operator-one", CredentialReferenceID: "ssh-one", CredentialMaterialVersion: "v1", StateRevision: 1, RecoveryEpoch: 0, CallerUID: 1001, IssuedAt: "2026-10-28T00:00:00Z", ExpiresAt: "2026-10-28T00:01:00Z"}
}
func TestHandlerExactIdentityAndSanitizedResult(t *testing.T) {
	r := &fixtureRuntime{result: Result{Changed: true, Verified: true}}
	h, _ := NewHandler(r)
	b := fixtureBundle(fixtureInput())
	v, e := h.Execute(context.Background(), b)
	if e != nil || v.Status != "succeeded" || h.Verify(context.Background(), b, v) != nil || r.calls != 1 {
		t.Fatal(v, e, r.calls)
	}
	for _, mutate := range []func(*generated.HostActionBundle){func(b *generated.HostActionBundle) { b.HostID = "other" }, func(b *generated.HostActionBundle) { b.ActionID = "arbitrary.install" }, func(b *generated.HostActionBundle) { b.ActionVersion = "2.0.0" }} {
		copy := b
		mutate(&copy)
		if _, e := h.Execute(context.Background(), copy); e == nil {
			t.Fatal("changed scope accepted")
		}
	}
	if r.calls != 1 {
		t.Fatal("denied action reached runtime")
	}
	r.err = denied()
	r.result.Verified = false
	v, e = h.Execute(context.Background(), b)
	if e != nil || v.Status != "partial" || !v.Changed {
		t.Fatal("partial effect lost", v, e)
	}
}
func TestInputRejectsProtectedHostUnknownFieldsAndPaths(t *testing.T) {
	for _, raw := range []string{`{"hostId":"vsk-node-04"}`, `{"hostId":"vsk-node-05"}`, `{"hostId":"x","token":"secret"}`, `{"hostId":"x","binaryPath":"/tmp/evil"}`} {
		if _, e := Decode([]byte(raw)); e == nil {
			t.Fatal("unsafe input accepted")
		}
	}
	in := fixtureInput()
	raw, _ := json.Marshal(in)
	if _, e := Decode(raw); e != nil {
		t.Fatal(e)
	}
	if strings.Contains(string(Unit(in)), " --token ") || !strings.Contains(string(Unit(in)), "--token-file %d/tunnel-token") {
		t.Fatal("credential exposed in unit")
	}
}
