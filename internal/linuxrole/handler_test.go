package linuxrole

import (
	"context"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"testing"
	"time"
)

type testRuntime struct {
	inspectErr error
	out        RoleResult
	effectErr  error
	called     bool
}

func (r *testRuntime) Inspect(context.Context, generated.HostActionBundle, generated.LinuxRoleInput) error {
	return r.inspectErr
}
func (r *testRuntime) Apply(context.Context, generated.HostActionBundle, generated.LinuxRoleInput) (RoleResult, error) {
	r.called = true
	return r.out, r.effectErr
}
func (r *testRuntime) Collect(context.Context, generated.HostActionBundle, generated.LinuxRoleInput) (RoleResult, error) {
	r.called = true
	return r.out, r.effectErr
}
func (r *testRuntime) Handoff(context.Context, generated.HostActionBundle, generated.LinuxRoleInput) (RoleResult, error) {
	r.called = true
	return r.out, r.effectErr
}
func handlerBundle(action string) generated.HostActionBundle {
	in := fixture()
	raw, _ := json.Marshal(in)
	d := hostaction.Digest("fixture")
	now := time.Now().UTC()
	return generated.HostActionBundle{Schema: generated.SchemaIDHostActionBundle, SchemaVersion: "1.0.0", ActionID: action, ActionVersion: "1.0.0", ActionInput: string(raw), ActionInputDigest: hostaction.BytesDigest(raw), BundleID: "bundle", PlanID: "plan", RunID: "run", StepID: "step", LeaseID: "lease", HostID: in.HostID, DeclarationID: "declaration", AutomationPrincipalID: "automation", CredentialReferenceID: "credential", CredentialMaterialVersion: "material", PlanDigest: d, HostIdentityDigest: in.HostIdentityDigest, ConsoleConfirmationDigest: d, DeclarationRevision: 1, StateRevision: 1, RecoveryEpoch: 1, CallerUID: in.AutomationUID, IssuedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(time.Minute).Format(time.RFC3339)}
}
func TestRoleCollectionCompletesReadWithoutChangedClaim(t *testing.T) {
	r := &testRuntime{}
	h, _ := NewHandler("debian.role.collect", r)
	out, e := h.Execute(context.Background(), handlerBundle("debian.role.collect"))
	if e != nil || !out.EffectObserved || out.Changed || out.Status != "succeeded" {
		t.Fatal(out, e)
	}
}
func TestRoleInterruptedMutationPersistsPartialMeasurements(t *testing.T) {
	r := &testRuntime{out: RoleResult{Changed: true}, effectErr: errNative}
	h, _ := NewHandler("debian.role.apply", r)
	out, e := h.Execute(context.Background(), handlerBundle("debian.role.apply"))
	if e != nil || !out.EffectObserved || !out.Changed || out.Status != "partial" || len(out.ControlMeasurements) == 0 || hostaction.ValidateResult(out) != nil {
		t.Fatal(out, e)
	}
	for _, m := range out.ControlMeasurements {
		if m.Status != "partial" || m.Role.Verification != "unavailable" {
			t.Fatal("invented completion")
		}
	}
}
func TestRolePreflightRefusalHasNoEffects(t *testing.T) {
	r := &testRuntime{inspectErr: errNative}
	h, _ := NewHandler("debian.role.apply", r)
	if _, e := h.Execute(context.Background(), handlerBundle("debian.role.apply")); e == nil || r.called {
		t.Fatal("preflight bypassed")
	}
	r.inspectErr = nil
	b := handlerBundle("debian.role.collect")
	if _, e := h.Execute(context.Background(), b); e == nil || r.called {
		t.Fatal("wrong action accepted")
	}
}
