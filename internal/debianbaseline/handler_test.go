package debianbaseline

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"testing"
	"time"
)

type collectorRuntime struct{ reader NativeReader }

func (collectorRuntime) Inspect(context.Context, generated.HostActionBundle, generated.DebianBaselineInput) error {
	return nil
}
func (collectorRuntime) Apply(context.Context, generated.HostActionBundle, generated.DebianBaselineInput) (Result, error) {
	return Result{}, errBaseline
}
func (r collectorRuntime) Collect(ctx context.Context, _ generated.HostActionBundle, in generated.DebianBaselineInput) (Result, error) {
	m, e := Collect(ctx, in, r.reader)
	return Result{Measurements: m}, e
}
func TestReadOnlyBaselineCollectionIsObservedAdapterEffect(t *testing.T) {
	in := baselineInputFixture()
	raw, _ := json.Marshal(in)
	b := testBundle("debian.baseline.collect", raw)
	h, _ := NewHandler(b.ActionID, collectorRuntime{fixtureReader{}})
	r, e := h.Execute(context.Background(), b)
	if e != nil {
		t.Fatal(e)
	}
	if r.Changed || !r.EffectObserved || len(r.ControlMeasurements) != 1 || r.ControlMeasurements[0].Status != "partial" {
		t.Fatal("read observation lost or fabricated qualification", r)
	}
	if e = adapter.ValidateEffect(adapter.Effect{Status: r.Status, Changed: r.Changed, EffectObserved: r.EffectObserved, ResultDigest: r.ResultDigest}); e != nil {
		t.Fatal(e)
	}
}
func TestRecoveryVerifierErrorCannotBecomeSuccessfulEmptyResult(t *testing.T) {
	base := baselineInputFixture()
	base.ProfileLock.Packages = []generated.AccessPackage{{Schema: generated.SchemaIDAccessPackage, SchemaVersion: "1.0.0", Name: "cryptsetup-bin", Version: "fixture"}}
	d := hostaction.Digest("fixture")
	binding := generated.HostVolumeBinding{Schema: generated.SchemaIDHostVolumeBinding, SchemaVersion: "1.0.0", HostID: "subject", HostIdentityDigest: hostaction.Digest("subject"), ControlHostID: "controller", ControlHostIdentityDigest: hostaction.Digest("controller"), VolumeID: "data", LUKSUUID: "11111111-2222-3333-4444-555555555555", HeaderBytes: 4096, HeaderDigest: d, MappingDigest: d, MountBindingDigest: d, MountPath: "/srv/data", MapperName: "data", DeviceMajor: 8, DeviceMinor: 1, KeySlot: 0, RecoveryCustodianID: "custodian", RecoveryCustodianIdentityDigest: d, RecoveryTargetDigest: d, RecoveryReferenceDigest: d, DeclarationID: "declaration", DeclarationRevision: 1, RecoveryEpoch: 0}
	in := generated.VolumeRecoveryInput{Schema: generated.SchemaIDVolumeRecoveryInput, SchemaVersion: "1.0.0", HostID: "custodian", HostIdentityDigest: d, ProfileID: base.ProfileID, ProfileLock: base.ProfileLock, ProfileLockDigest: hostaction.Digest(base.ProfileLock), RoleID: "host", ActionVersion: "1.0.0", AutomationUID: 1001, Binding: binding, PriorVolumeReceiptDigest: d, RecoveryReferenceID: "recovery-data", RecoveryMaterialVersion: "v1"}
	raw, _ := json.Marshal(in)
	if _, e := DecodeRecoveryInput(raw); e != nil {
		t.Fatal("test must reach actual verifier", e)
	}
	b := testBundle("debian.volume-recovery.verify", raw)
	h0, _ := NewHandler(b.ActionID, collectorRuntime{})
	h := h0.(handler)
	want := errors.New("native verifier failed")
	h.verifyRecovery = func(context.Context, generated.VolumeRecoveryInput) ([]generated.AccessMeasurement, error) {
		return nil, want
	}
	r, e := h.Execute(context.Background(), b)
	if !errors.Is(e, want) || r.Status == "succeeded" {
		t.Fatal("verification error swallowed", r, e)
	}
}

func testBundle(action string, raw []byte) generated.HostActionBundle {
	d := hostaction.Digest("fixture")
	now := time.Now().UTC()
	return generated.HostActionBundle{Schema: generated.SchemaIDHostActionBundle, SchemaVersion: "1.0.0", ActionID: action, ActionVersion: "1.0.0", ActionInput: string(raw), ActionInputDigest: hostaction.BytesDigest(raw), BundleID: "bundle", PlanID: "plan", RunID: "run", StepID: "step", LeaseID: "lease", HostID: "host", DeclarationID: "declaration", AutomationPrincipalID: "automation", CredentialReferenceID: "credential", CredentialMaterialVersion: "material", PlanDigest: d, HostIdentityDigest: d, ConsoleConfirmationDigest: d, DeclarationRevision: 1, StateRevision: 1, RecoveryEpoch: 1, CallerUID: 1001, IssuedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(time.Minute).Format(time.RFC3339)}
}
