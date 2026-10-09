package linuxrole

import (
	"context"
	"errors"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"time"
)

var errNative = errors.New("Linux role native operation refused")

type RoleResult struct {
	Changed      bool
	Pending      bool
	Measurements []generated.AccessMeasurement
}
type Runtime interface {
	Inspect(context.Context, generated.HostActionBundle, generated.LinuxRoleInput) error
	Apply(context.Context, generated.HostActionBundle, generated.LinuxRoleInput) (RoleResult, error)
	Collect(context.Context, generated.HostActionBundle, generated.LinuxRoleInput) (RoleResult, error)
	Handoff(context.Context, generated.HostActionBundle, generated.LinuxRoleInput) (RoleResult, error)
}
type handler struct {
	action  string
	runtime Runtime
}

func NewHandler(action string, r Runtime) (hostaction.Handler, error) {
	if r == nil {
		return nil, errNative
	}
	switch action {
	case "debian.role.apply", "debian.role.collect", "debian.control.handoff", "debian.control.handoff.verify":
		return handler{action, r}, nil
	}
	return nil, errNative
}
func (h handler) Execute(ctx context.Context, b generated.HostActionBundle) (generated.HostActionResult, error) {
	r := generated.HostActionResult{Schema: generated.SchemaIDHostActionResult, SchemaVersion: "1.0.0"}
	if b.ActionID != h.action || b.ActionVersion != "1.0.0" || b.VerificationEvidence != nil || b.VerificationEvidenceDigest != "" {
		return r, errNative
	}
	in, e := DecodeInput([]byte(b.ActionInput))
	if e != nil {
		return r, e
	}
	if (h.action == "debian.control.handoff" || h.action == "debian.control.handoff.verify") != (in.Handoff != nil) {
		return r, errNative
	}
	if e = h.runtime.Inspect(ctx, b, in); e != nil {
		return r, e
	}
	bd, e := hostaction.BundleDigest(b)
	if e != nil {
		return r, e
	}
	r.BundleDigest = bd
	var out RoleResult
	switch h.action {
	case "debian.role.apply":
		out, e = h.runtime.Apply(ctx, b, in)
	case "debian.role.collect":
		out, e = h.runtime.Collect(ctx, b, in)
	default:
		out, e = h.runtime.Handoff(ctx, b, in)
	}
	if e != nil && !out.Changed {
		return r, e
	}
	r.Changed = out.Changed
	r.EffectObserved = out.Changed || e == nil
	if len(out.Measurements) == 0 && out.Changed {
		out.Measurements = incompleteMeasurements(in, bd)
	}
	r.ControlMeasurements = out.Measurements
	r.Status = "succeeded"
	r.Reason = "native-role-observed"
	if e != nil || out.Pending {
		r.Status = "partial"
		r.Reason = "role-effect-incomplete"
	}
	for i := range r.ControlMeasurements {
		m := &r.ControlMeasurements[i]
		m.BundleDigest = bd
		m.MeasurementDigest = hostaction.MeasurementDigest(*m)
		if m.Status != "passed" {
			r.Status = "partial"
			r.Reason = "role-verification-incomplete"
		}
	}
	r.ResultDigest = hostaction.ResultDigest(r)
	if hostaction.ValidateResult(r) != nil {
		return generated.HostActionResult{}, errNative
	}
	return r, nil
}
func (h handler) Verify(_ context.Context, b generated.HostActionBundle, r generated.HostActionResult) error {
	d, e := hostaction.BundleDigest(b)
	if e != nil || b.ActionID != h.action || r.BundleDigest != d {
		return errNative
	}
	return hostaction.ValidateResult(r)
}

type dispatcher struct{ runtime Runtime }

func NewDispatcher(r Runtime) hostaction.Dispatcher { return dispatcher{r} }
func (d dispatcher) Lookup(id, version string) (hostaction.Handler, bool) {
	if version != "1.0.0" {
		return nil, false
	}
	h, e := NewHandler(id, d.runtime)
	return h, e == nil
}

func incompleteMeasurements(in generated.LinuxRoleInput, bundle string) []generated.AccessMeasurement {
	out := []generated.AccessMeasurement{}
	for _, id := range in.ControlIDs {
		out = append(out, generated.AccessMeasurement{Schema: generated.SchemaIDAccessMeasurement, SchemaVersion: "1.0.0", ControlID: id, Kind: "role", Status: "partial", Reason: "role-effect-incomplete", SubjectHostID: in.HostID, SubjectIdentityDigest: in.HostIdentityDigest, ProfileLockDigest: in.ProfileLockDigest, ProducerID: "linux-role", ProducerVersion: "1.0.0", ObservedAt: time.Now().UTC().Format(time.RFC3339), ConfigurationDigest: hostaction.Digest(in), PositiveProbeDigest: hostaction.BytesDigest(nil), NegativeProbeDigest: hostaction.BytesDigest(nil), Role: &generated.RoleObservation{Schema: generated.SchemaIDRoleObservation, SchemaVersion: "1.0.0", RoleID: in.RoleID, RoleBindingDigest: in.RoleBindingDigest, FactsDigest: hostaction.Digest(map[string]string{"bundle": bundle, "status": "effect-incomplete"}), Verification: "unavailable"}})
	}
	return out
}
