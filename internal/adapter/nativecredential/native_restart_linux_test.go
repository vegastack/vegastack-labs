//go:build linux

package nativecredential

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"os"
	"strings"
	"testing"
)

type restartTestAuthority struct {
	restarts, queued, probes int
	openDenied               bool
}

func (a *restartTestAuthority) Restart(context.Context, string) (RestartReceipt, error) {
	a.restarts++
	return RestartReceipt{}, errProbeBlocked
}
func (a *restartTestAuthority) EnqueueRestart(context.Context, string) error { a.queued++; return nil }
func (a *restartTestAuthority) Probe(context.Context, AccessProbeRequest) (AccessProbeResult, error) {
	a.probes++
	if a.openDenied {
		return AccessProbeResult{Status: AccessProbeOpened, Device: 1, Inode: 1, Mode: 0100400}, nil
	}
	return AccessProbeResult{Status: AccessProbeDenied}, nil
}

type restartTestUnits struct{ unit AppliedUnitSnapshot }

func (u restartTestUnits) ObserveAppliedUnit(context.Context, string) (AppliedUnitSnapshot, error) {
	return u.unit, nil
}
func TestNativeRestartContinuationNeverRestarts(t *testing.T) {
	ctx := context.Background()
	r, _ := loadedReceiptFixture()
	b := r.Binding
	b.ConsumerIDs = []string{"host-action"}
	b.NativeArtifactConsumerID = "host-action"
	b.NativeConsumers[0].ConsumerID = "host-action"
	b.NativeConsumers[0].LoadedName = credentialref.LoadedNameForVersion("host-action", b.ReferenceID, b.MaterialVersion)
	b.HostActionConsole = &credentialref.HostActionConsoleBinding{Method: "administrator-verified-console", TargetDigest: b.CiphertextFingerprint, HostIdentityDigest: b.CiphertextFingerprint, TargetRevision: 1, NativeConsumerMachineID: b.NativeConsumers[0].HostMachineID}
	proof := r.Proof
	proof.MainPID = uint32(os.Getpid())
	proof.InvocationID = strings.Repeat("c", 32)
	p := credentialref.NativeRestartPending{Version: 1, PlanID: "plan-prior", PlanDigest: r.PlanDigest, RunID: "run-prior", StepID: "step-prior", LeaseID: "lease-prior", Binding: b, Before: credentialref.NativeRestartBefore{ConsumerID: "host-action", MachineID: b.NativeConsumers[0].HostMachineID, BootID: proof.BootID, InvocationID: strings.Repeat("b", 32), MainPID: 42, ProcessStartTicks: 1, SourceDevice: proof.SourceDevice, SourceInode: proof.SourceInode, SourceFingerprint: proof.SourceFingerprint, RequestMonotonicNanos: 1000000}}
	if !credentialref.ValidNativeRestartPending(p) {
		t.Fatal("invalid test pending")
	}
	authority := &restartTestAuthority{}
	v := &NativeLifecycleVerifier{Authority: authority, Units: restartTestUnits{AppliedUnitSnapshot{InvocationID: proof.InvocationID, MainPID: proof.MainPID, ExecMainStartMonotonicUSec: 1001}}, policy: func(credentialref.LifecycleBinding) error { return nil }, current: func(context.Context, credentialref.LifecycleBinding, credentialref.NativeConsumerBinding) (NativeInvocationProof, error) {
		return proof, nil
	}, recheck: func(context.Context, credentialref.LifecycleBinding, credentialref.NativeConsumerBinding, NativeInvocationProof) error {
		return nil
	}}
	c, err := v.CaptureNativeRestartContinuation(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	b.NativeRestartContinuation = c
	b.OperationID = "complete-a"
	b.StateRevision++
	step := NativeVerificationStep{OperationID: b.OperationID, OperationType: string(b.Action), TargetID: b.TargetID, ArtifactDigest: b.CiphertextFingerprint, PlanDigest: r.PlanDigest, RunID: "run-complete", StepID: "step-complete"}
	got, err := v.VerifyNativeContinuation(ctx, step, b, p)
	if err != nil || len(got) != 2 || got[0].NativeReceipt == nil || got[0].NativeReceipt.RunID != step.RunID || authority.probes != 1 {
		t.Fatal("read-only continuation failed", err)
	}
	for _, change := range []string{"source", "invocation", "epoch", "attempt", "denied"} {
		t.Run(change, func(t *testing.T) {
			copyB := b
			copyC := *c
			copyB.NativeRestartContinuation = &copyC
			switch change {
			case "source":
				copyC.Expected.SourceInode++
			case "invocation":
				copyC.Expected.InvocationID = strings.Repeat("d", 32)
			case "epoch":
				copyB.RecoveryEpoch++
			case "attempt":
				copyC.PriorRunID = "unrelated"
			case "denied":
				authority.openDenied = true
				defer func() { authority.openDenied = false }()
			}
			if _, err := v.VerifyNativeContinuation(ctx, step, copyB, p); err == nil {
				t.Fatal("invalid continuation accepted")
			}
		})
	}
	if authority.restarts != 0 || authority.queued != 0 {
		t.Fatal("completion issued restart")
	}
}
