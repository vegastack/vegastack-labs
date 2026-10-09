package credentialref

import (
	"strings"
	"testing"
)

func restartPendingFixture() NativeRestartPending {
	r := nativeReceiptFixture()
	b := r.Binding
	b.ConsumerIDs = []string{"host-action"}
	b.NativeArtifactConsumerID = "host-action"
	b.NativeConsumers = b.NativeConsumers[:1]
	b.NativeConsumers[0].ConsumerID = "host-action"
	b.NativeConsumers[0].LoadedName = LoadedNameForVersion("host-action", b.ReferenceID, b.MaterialVersion)
	b.HostActionConsole = &HostActionConsoleBinding{Method: "administrator-verified-console", TargetDigest: b.CiphertextFingerprint, HostIdentityDigest: b.CiphertextFingerprint, TargetRevision: 1}
	return NativeRestartPending{Version: 1, PlanID: "plan-prior", PlanDigest: r.PlanDigest, RunID: "run-prior", StepID: "step-prior", LeaseID: "lease-prior", Binding: b, Before: NativeRestartBefore{ConsumerID: "host-action", MachineID: b.NativeConsumers[0].HostMachineID, BootID: r.Proof.BootID, InvocationID: r.Proof.InvocationID, MainPID: r.Proof.MainPID, ProcessStartTicks: r.Proof.ProcessStartTicks, SourceDevice: r.Proof.SourceDevice, SourceInode: r.Proof.SourceInode, SourceFingerprint: r.Proof.SourceFingerprint, RequestMonotonicNanos: 1}}
}
func TestNativeRestartPendingCanonicalAndExact(t *testing.T) {
	p := restartPendingFixture()
	raw, err := EncodeNativeRestartPending(p)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeNativeRestartPending(raw)
	if err != nil || NativeRestartPendingDigest(decoded) != NativeRestartPendingDigest(p) {
		t.Fatal("lost pending identity", err)
	}
	if _, err := DecodeNativeRestartPending(append(raw, ' ')); err == nil {
		t.Fatal("noncanonical pending accepted")
	}
	b := p.Binding
	b.OperationID = "complete-a"
	b.StateRevision++
	proof := nativeReceiptFixture().Proof
	proof.InvocationID = strings.Repeat("c", 32)
	b.NativeRestartContinuation = &NativeRestartContinuation{PriorRunID: p.RunID, PriorStepID: p.StepID, PendingDigest: NativeRestartPendingDigest(p), Expected: proof}
	if !ValidLifecycleBinding(b) || !PendingMatchesLifecycle(p, b) {
		t.Fatal("exact continuation refused")
	}
	for _, change := range []string{"source", "epoch", "attempt", "version", "console", "same-invocation", "boot"} {
		t.Run(change, func(t *testing.T) {
			copyB := b
			copyC := *b.NativeRestartContinuation
			copyB.NativeRestartContinuation = &copyC
			switch change {
			case "source":
				copyC.Expected.SourceInode++
			case "epoch":
				copyB.RecoveryEpoch++
			case "attempt":
				copyC.PriorRunID = "other"
			case "version":
				copyB.MaterialVersion = "other"
			case "console":
				c := *copyB.HostActionConsole
				c.TargetRevision++
				copyB.HostActionConsole = &c
			case "same-invocation":
				copyC.Expected.InvocationID = p.Before.InvocationID
			case "boot":
				copyC.Expected.BootID = "00000000-0000-0000-0000-000000000002"
			}
			if PendingMatchesLifecycle(p, copyB) {
				t.Fatal("mismatched continuation accepted")
			}
		})
	}
}
