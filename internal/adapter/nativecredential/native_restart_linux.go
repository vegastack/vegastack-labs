//go:build linux

package nativecredential

import (
	"context"
	"os"
	"path/filepath"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
)

// PrepareNativeRestart observes an exact single self-consumer before any
// restart. False leaves all unrelated lifecycle execution on its existing path.
func (v *NativeLifecycleVerifier) PrepareNativeRestart(ctx context.Context, step NativeVerificationStep, b credentialref.LifecycleBinding) (credentialref.NativeRestartPending, bool, error) {
	var zero credentialref.NativeRestartPending
	if b.HostActionConsole == nil || b.NativeRestartContinuation != nil {
		return zero, false, nil
	}
	if v == nil || v.Units == nil || v.current == nil || len(b.NativeConsumers) != 1 || !credentialref.ValidLifecycleBinding(b) {
		return zero, false, errNativeLifecycle
	}
	r := b.NativeConsumers[0]
	unit, err := v.Units.ObserveAppliedUnit(ctx, r.UnitName)
	if err != nil {
		return zero, false, errNativeLifecycle
	}
	if int(unit.MainPID) != os.Getpid() {
		return zero, true, errNativeLifecycle
	}
	if v.policy(b) != nil || step.OperationID != b.OperationID || step.OperationType != string(b.Action) || step.TargetID != b.TargetID || step.ArtifactDigest != b.CiphertextFingerprint {
		return zero, true, errNativeLifecycle
	}
	before, err := v.restartBefore(ctx, b, r)
	if err != nil {
		return zero, true, err
	}
	p := credentialref.NativeRestartPending{Version: 1, PlanID: step.PlanID, PlanDigest: step.PlanDigest, RunID: step.RunID, StepID: step.StepID, LeaseID: step.LeaseID, Binding: b, Before: before}
	if !credentialref.ValidNativeRestartPending(p) {
		return zero, true, errNativeLifecycle
	}
	return p, true, nil
}
func (v *NativeLifecycleVerifier) EnqueueNativeRestart(ctx context.Context, p credentialref.NativeRestartPending) error {
	if !credentialref.ValidNativeRestartPending(p) || v == nil || v.current == nil || v.policy(p.Binding) != nil {
		return errNativeLifecycle
	}
	r := p.Binding.NativeConsumers[0]
	before, err := v.restartBefore(ctx, p.Binding, r)
	if err != nil || before.RequestMonotonicNanos < p.Before.RequestMonotonicNanos {
		return errNativeLifecycle
	}
	before.RequestMonotonicNanos = p.Before.RequestMonotonicNanos
	if before != p.Before {
		return errNativeLifecycle
	}
	a, ok := v.Authority.(interface {
		EnqueueRestart(context.Context, string) error
	})
	if !ok {
		return errNativeLifecycle
	}
	return a.EnqueueRestart(ctx, r.UnitName)
}
func (v *NativeLifecycleVerifier) CaptureNativeRestartContinuation(ctx context.Context, p credentialref.NativeRestartPending) (*credentialref.NativeRestartContinuation, error) {
	if !credentialref.ValidNativeRestartPending(p) || v == nil || v.current == nil || v.policy(p.Binding) != nil {
		return nil, errNativeLifecycle
	}
	r := p.Binding.NativeConsumers[0]
	proof, err := v.current(ctx, p.Binding, r)
	if err != nil || int(proof.MainPID) != os.Getpid() || proof.BootID != p.Before.BootID || proof.InvocationID == p.Before.InvocationID || proof.SourceDevice != p.Before.SourceDevice || proof.SourceInode != p.Before.SourceInode || proof.SourceFingerprint != p.Before.SourceFingerprint {
		return nil, errNativeLifecycle
	}
	unit, err := v.Units.ObserveAppliedUnit(ctx, r.UnitName)
	if err != nil || unit.InvocationID != proof.InvocationID || unit.MainPID != proof.MainPID || unit.ExecMainStartMonotonicUSec < uint64(p.Before.RequestMonotonicNanos/1000) {
		return nil, errNativeLifecycle
	}
	c := &credentialref.NativeRestartContinuation{PriorRunID: p.RunID, PriorStepID: p.StepID, PendingDigest: credentialref.NativeRestartPendingDigest(p), Expected: proof}
	if !credentialref.ValidNativeRestartContinuation(c) {
		return nil, errNativeLifecycle
	}
	return c, nil
}
func (v *NativeLifecycleVerifier) VerifyNativeContinuation(ctx context.Context, step NativeVerificationStep, b credentialref.LifecycleBinding, p credentialref.NativeRestartPending) ([]credentialref.ConsumerVerification, error) {
	if !credentialref.PendingMatchesLifecycle(p, b) {
		return nil, errNativeLifecycle
	}
	c, err := v.CaptureNativeRestartContinuation(ctx, p)
	if err != nil || *c != *b.NativeRestartContinuation {
		return nil, errNativeLifecycle
	}
	// Reuse actual denied probes and final rechecks; only the restart-producing
	// observer is replaced by the exact just-observed invocation, never a boolean.
	observed := *v
	observed.observe = func(ctx context.Context, b credentialref.LifecycleBinding, r credentialref.NativeConsumerBinding) (NativeInvocationProof, error) {
		if r.ConsumerID != p.Before.ConsumerID || v.recheck(ctx, b, r, c.Expected) != nil {
			return NativeInvocationProof{}, errNativeLifecycle
		}
		return c.Expected, nil
	}
	return observed.VerifyNative(ctx, step, b)
}
func (v *NativeLifecycleVerifier) currentNativeProof(ctx context.Context, b credentialref.LifecycleBinding, r credentialref.NativeConsumerBinding) (NativeInvocationProof, error) {
	var zero NativeInvocationProof
	if ctx == nil || ctx.Err() != nil || v == nil || v.Units == nil || v.Authority == nil {
		return zero, errNativeLifecycle
	}
	unit, err := v.Units.ObserveAppliedUnit(ctx, r.UnitName)
	if err != nil || unit.MachineID != r.HostMachineID || !unitIdentityMatches(unit, r) || validateAppliedSource(unit, b, r, filepath.Join(v.CiphertextRoot, r.LoadedName)) != nil {
		return zero, errNativeLifecycle
	}
	source, err := InspectEncrypted(ctx, InspectRequest{Name: r.LoadedName, CiphertextDirectory: v.CiphertextRoot, ExpectedUID: v.CiphertextOwnerUID})
	if err != nil || source.State != "present" || source.Fingerprint != b.CiphertextFingerprint {
		return zero, errNativeLifecycle
	}
	process, err := observeProcessIdentity(ctx, unit, r)
	if err != nil {
		return zero, errNativeLifecycle
	}
	loaded, err := v.Authority.Probe(ctx, AccessProbeRequest{UID: r.ServiceUID, GID: r.ServiceGID, UnitName: r.UnitName, CredentialName: r.LoadedName, MainPID: int(unit.MainPID), ProcessStartTicks: process.StartTicks, BootID: unit.BootID})
	if err != nil || !validProbeResult(loaded) || loaded.Status != AccessProbeOpened {
		return zero, errNativeLifecycle
	}
	proof := NativeInvocationProof{BootID: unit.BootID, InvocationID: unit.InvocationID, MainPID: unit.MainPID, ProcessStartTicks: process.StartTicks, NamespaceDevice: loaded.NamespaceDevice, NamespaceInode: loaded.NamespaceInode, CredentialDevice: loaded.Device, CredentialInode: loaded.Inode, CredentialUID: loaded.OwnerUID, CredentialGID: loaded.OwnerGID, CredentialMode: loaded.Mode, SourceDevice: source.Device, SourceInode: source.Inode, SourceFingerprint: source.Fingerprint}
	if !validNativeProof(proof, r, b) || v.recheck(ctx, b, r, proof) != nil {
		return zero, errNativeLifecycle
	}
	return proof, nil
}

// restartBefore does not require the NEW loaded file in the OLD process. It
// observes only the installed encrypted source and pre-restart process identity.
func (v *NativeLifecycleVerifier) restartBefore(ctx context.Context, b credentialref.LifecycleBinding, r credentialref.NativeConsumerBinding) (credentialref.NativeRestartBefore, error) {
	var zero credentialref.NativeRestartBefore
	if ctx == nil || ctx.Err() != nil {
		return zero, errNativeLifecycle
	}
	unit, err := v.Units.ObserveAppliedUnit(ctx, r.UnitName)
	if err != nil || int(unit.MainPID) != os.Getpid() || unit.MachineID != r.HostMachineID || !unitIdentityMatches(unit, r) || validateAppliedSource(unit, b, r, filepath.Join(v.CiphertextRoot, r.LoadedName)) != nil {
		return zero, errNativeLifecycle
	}
	source, err := InspectEncrypted(ctx, InspectRequest{Name: r.LoadedName, CiphertextDirectory: v.CiphertextRoot, ExpectedUID: v.CiphertextOwnerUID})
	if err != nil || source.State != "present" || source.Fingerprint != b.CiphertextFingerprint {
		return zero, errNativeLifecycle
	}
	process, err := observeProcessIdentity(ctx, unit, r)
	if err != nil {
		return zero, errNativeLifecycle
	}
	again, err := v.Units.ObserveAppliedUnit(ctx, r.UnitName)
	if err != nil || !sameInvocation(unit, again) {
		return zero, errNativeLifecycle
	}
	sourceAgain, err := InspectEncrypted(ctx, InspectRequest{Name: r.LoadedName, CiphertextDirectory: v.CiphertextRoot, ExpectedUID: v.CiphertextOwnerUID})
	if err != nil || sourceAgain != source {
		return zero, errNativeLifecycle
	}
	floor, err := monotonicNanos()
	if err != nil {
		return zero, errNativeLifecycle
	}
	return credentialref.NativeRestartBefore{ConsumerID: r.ConsumerID, MachineID: r.HostMachineID, BootID: unit.BootID, InvocationID: unit.InvocationID, MainPID: unit.MainPID, ProcessStartTicks: process.StartTicks, SourceDevice: source.Device, SourceInode: source.Inode, SourceFingerprint: source.Fingerprint, RequestMonotonicNanos: floor}, nil
}
