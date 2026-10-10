package qualification

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/linuxrole"
	"time"
)

func ControlHandoffWitness(in linuxrole.NativeControlHandoffObservation) generated.NativeControlHandoffWitness {
	return generated.NativeControlHandoffWitness{Schema: generated.SchemaIDNativeControlHandoffWitness, SchemaVersion: "1.0.0", Bundle: in.Bundle, Input: in.Input, ReceiptDigest: in.ReceiptDigest, RecordedState: controlServiceWitness(in.RecordedState), CurrentState: controlServiceWitness(in.CurrentState), ObservedAt: in.ObservedAt}
}
func controlServiceWitness(s linuxrole.ControlServiceState) generated.NativeControlServiceState {
	return generated.NativeControlServiceState{Schema: generated.SchemaIDNativeControlServiceState, SchemaVersion: "1.0.0", DatabaseInstanceID: s.DatabaseInstanceID, RecoveryEpoch: s.RecoveryEpoch, ServiceUID: s.ServiceUID, PID: s.PID, StartIdentity: s.StartIdentity, WriterLockDigest: s.WriterLockDigest, UnitDigest: s.UnitDigest, ConfigDigest: s.ConfigDigest, ExecutableDigest: s.ExecutableDigest, SocketIdentityDigest: s.SocketIdentityDigest, ServiceActive: s.ServiceActive, Healthy: s.Healthy}
}
func nativeControlState(s generated.NativeControlServiceState) linuxrole.ControlServiceState {
	return linuxrole.ControlServiceState{DatabaseInstanceID: s.DatabaseInstanceID, RecoveryEpoch: s.RecoveryEpoch, ServiceUID: s.ServiceUID, PID: s.PID, StartIdentity: s.StartIdentity, WriterLockDigest: s.WriterLockDigest, UnitDigest: s.UnitDigest, ConfigDigest: s.ConfigDigest, ExecutableDigest: s.ExecutableDigest, SocketIdentityDigest: s.SocketIdentityDigest, ServiceActive: s.ServiceActive, Healthy: s.Healthy}
}

// ValidateControlHandoffEvidence binds a genuine successful fresh verification
// run to the independently read original handoff receipt and current writer.
// The original handoff enqueue is deliberately not reclassified as success.
func ValidateControlHandoffEvidence(e ProducerExecution, w generated.NativeControlHandoffWitness, at time.Time) error {
	if !exactNativeJSON(generated.SchemaIDNativeControlHandoffWitness, w) || e.Plan.HostAction == nil || e.Plan.HostAction.ActionID != "debian.control.handoff.verify" || e.Result == nil || e.Result.Status != "succeeded" || e.Receipt.Status != "succeeded" || e.Reference.HostID != w.Input.HostID || w.Bundle.HostID != w.Input.HostID || w.Bundle.HostIdentityDigest != w.Input.HostIdentityDigest || w.Bundle.ActionID != "debian.control.handoff" || w.Bundle.ActionInputDigest != hostaction.Digest(w.Input) || w.Input.Handoff == nil || w.Bundle.RecoveryEpoch != w.Input.Handoff.RecoveryEpoch {
		return ErrUnavailable
	}
	in, err := linuxrole.DecodeInput([]byte(e.Plan.HostAction.ActionInput))
	if err != nil || in.RoleID != "control" || in.HostID != w.Input.HostID || in.HostIdentityDigest != w.Input.HostIdentityDigest || in.RoleBindingDigest != w.Input.RoleBindingDigest || hostaction.Digest(in.Handoff) != hostaction.Digest(w.Input.Handoff) || e.Plan.Binding.RecoveryEpoch != w.Bundle.RecoveryEpoch {
		return ErrUnavailable
	}
	recorded, current := nativeControlState(w.RecordedState), nativeControlState(w.CurrentState)
	if !recorded.ServiceActive || !current.ServiceActive || linuxrole.ValidateControlHandoff(w.Input, recorded) != nil || linuxrole.ValidateControlHandoff(in, current) != nil {
		return ErrUnavailable
	}
	// Match the existing production HandoffReceipt encoding; generated schema
	// envelope fields are not part of its stored ControlServiceState bytes.
	receipt := struct {
		Bundle generated.HostActionBundle    `json:"bundle"`
		Input  generated.LinuxRoleInput      `json:"input"`
		Status string                        `json:"status"`
		State  linuxrole.ControlServiceState `json:"state"`
		Digest string                        `json:"digest"`
	}{w.Bundle, w.Input, "completed", recorded, ""}
	if hostaction.Digest(receipt) != w.ReceiptDigest {
		return ErrUnavailable
	}
	observed, err := time.Parse(time.RFC3339Nano, w.ObservedAt)
	if err != nil || at.Before(observed) || at.Sub(observed) > 30*time.Second {
		return ErrUnavailable
	}
	for _, m := range e.Result.ControlMeasurements {
		if m.ControlID == "linux.control-service" && m.Status == "passed" && m.Role != nil && m.Role.RoleBindingDigest == in.RoleBindingDigest && m.Role.Verification == "effective-probe" {
			return nil
		}
	}
	return ErrUnavailable
}

// ValidateOriginalControlHandoffEvidence preserves the original honest pending
// outcome and binds it to the worker's completed protected receipt. Transport
// failures/effect-unknown records do not meet this predicate.
func ValidateOriginalControlHandoffEvidence(e ProducerExecution, w generated.NativeControlHandoffWitness) error {
	b, p, r, x := w.Bundle, e.Plan, e.Reference, e.Receipt
	if p.HostAction == nil || p.HostAction.ActionID != "debian.control.handoff" || r.ScenarioID != "control-handoff" || x.Status != "partial" || e.Result == nil || e.Result.Status != "partial" || !e.Result.Changed || !e.Result.EffectObserved || e.Result.ResultDigest != x.ResultDigest || e.Result.BundleDigest != hostaction.Digest(b) || p.PlanID != b.PlanID || p.PlanDigest != b.PlanDigest || r.RunID != b.RunID || r.StepID != b.StepID || r.LeaseID != b.LeaseID || x.RunID != b.RunID || x.StepID != b.StepID || x.LeaseID != b.LeaseID || x.PlanID != b.PlanID || x.PlanDigest != b.PlanDigest || p.Binding.RecoveryEpoch != b.RecoveryEpoch || r.HostID != b.HostID || p.HostAction.ActionInputDigest != b.ActionInputDigest {
		return ErrUnavailable
	}
	in, err := linuxrole.DecodeInput([]byte(p.HostAction.ActionInput))
	if err != nil || hostaction.Digest(in) != hostaction.Digest(w.Input) || hostaction.Digest(in) != b.ActionInputDigest {
		return ErrUnavailable
	}
	for _, m := range e.Result.ControlMeasurements {
		if m.ControlID == "linux.control-service" && m.Status == "partial" && m.Role != nil && m.Role.RoleBindingDigest == in.RoleBindingDigest {
			return nil
		}
	}
	return ErrUnavailable
}
