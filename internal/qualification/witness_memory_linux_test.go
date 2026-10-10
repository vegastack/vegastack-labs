//go:build linux

package qualification

import (
	"context"
	"errors"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"testing"
	"time"
)

func TestNativeWitnessMemoryDoesNotAcceptMismatchedOrReplayedCapture(t *testing.T) {
	scope, err := validateScope(scopeFixture())
	if err != nil {
		t.Fatal(err)
	}
	d := &ownedGuestLifecycle{scope: scope, witnesses: map[string]*nativeWitnessMemory{}}
	in := generated.NativeStepRequest{ScopeDigest: scope.digest, ControllerInstanceID: scope.value.ControllerInstanceID, PlanDigest: hostaction.Digest("plan"), GuestID: "subject", ScenarioID: "volume-sealed-copy-write-refused", Operation: "witness", PlanID: "plan", RunID: "run", StepID: "step", LeaseID: "lease", Nonce: hostaction.Digest("nonce")}
	value := generated.NativeVolumeSealWitness{HeaderBeforeDigest: hostaction.Digest("actual sampled header")}
	out := generated.NativeStepResult{Binding: in, Status: "completed", VolumeSeal: &value}
	wrong := out
	wrong.Binding.RunID = "other-run"
	if d.captureWitness(in, wrong) == nil {
		t.Fatal("mismatched response captured")
	}
	if len(d.witnesses) != 0 {
		t.Fatal("mismatched capture populated memory")
	}
	if err = d.captureWitness(in, out); err != nil {
		t.Fatal(err)
	}
	out.VolumeSeal = &generated.NativeVolumeSealWitness{HeaderBeforeDigest: hostaction.Digest("replacement")}
	if d.captureWitness(in, out) == nil {
		t.Fatal("replay overwrote memory")
	}
	binding := generated.NativeObservationBinding{ScopeDigest: scope.digest, ControllerInstanceID: scope.value.ControllerInstanceID, GuestID: "subject", PlanDigest: in.PlanDigest, ScenarioID: in.ScenarioID, PlanID: in.PlanID, RunID: in.RunID, StepID: in.StepID, LeaseID: in.LeaseID}
	var observed generated.NativeObservation
	d.attachWitness(binding, &observed)
	if observed.VolumeSeal == nil || observed.VolumeSeal.HeaderBeforeDigest != value.HeaderBeforeDigest {
		t.Fatal("original sample not preserved")
	}
	for name, mutate := range map[string]func(*generated.NativeObservationBinding){
		"epoch":       func(b *generated.NativeObservationBinding) { b.RecoveryEpoch++ },
		"plan-digest": func(b *generated.NativeObservationBinding) { b.PlanDigest = hostaction.Digest("other") },
		"controller":  func(b *generated.NativeObservationBinding) { b.ControllerInstanceID = "other" },
		"scope":       func(b *generated.NativeObservationBinding) { b.ScopeDigest = hostaction.Digest("other") },
	} {
		t.Run(name, func(t *testing.T) {
			altered := binding
			mutate(&altered)
			got := generated.NativeObservation{}
			d.attachWitness(altered, &got)
			if got.VolumeSeal != nil {
				t.Fatal("witness transplanted across binding")
			}
		})
	}
	binding.LeaseID = "other-lease"
	observed = generated.NativeObservation{}
	d.attachWitness(binding, &observed)
	if observed.VolumeSeal != nil {
		t.Fatal("witness transplanted across lease")
	}
	fresh := &ownedGuestLifecycle{scope: scope, witnesses: map[string]*nativeWitnessMemory{}}
	observed = generated.NativeObservation{}
	binding.LeaseID = in.LeaseID
	fresh.attachWitness(binding, &observed)
	if observed.VolumeSeal != nil {
		t.Fatal("new process rehydrated unobserved witness")
	}
}

func TestFail2banWaitCancellationCannotProduceCompletedCycle(t *testing.T) {
	scope, err := validateScope(scopeFixture())
	if err != nil {
		t.Fatal(err)
	}
	in := generated.NativeStepRequest{ScopeDigest: scope.digest, ControllerInstanceID: scope.value.ControllerInstanceID, ScenarioID: "fail2ban-window", Operation: "witness", GuestID: "subject", PlanID: "plan", PlanDigest: hostaction.Digest("plan"), RunID: "run", StepID: "step", LeaseID: "lease"}
	w := &nativeWitnessMemory{guest: "subject", phase: 5, banAt: time.Now(), fail: &generated.NativeFail2banWitness{}}
	d := &ownedGuestLifecycle{scope: scope, witnesses: map[string]*nativeWitnessMemory{witnessKey(in): w}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if !errors.Is(d.waitWitnessWindow(ctx, in), context.Canceled) {
		t.Fatal("600 second wait ignored cancellation")
	}
	if w.phase != 5 {
		t.Fatal("cancelled wait advanced cycle")
	}
	b := generated.NativeObservationBinding{ScopeDigest: in.ScopeDigest, ControllerInstanceID: in.ControllerInstanceID, ScenarioID: in.ScenarioID, GuestID: in.GuestID, PlanID: in.PlanID, PlanDigest: in.PlanDigest, RunID: in.RunID, StepID: in.StepID, LeaseID: in.LeaseID}
	var out generated.NativeObservation
	d.attachWitness(b, &out)
	if out.Fail2banCycle != nil {
		t.Fatal("incomplete cancelled cycle exported")
	}
}

func TestNativeCredentialSamplesRemainEpochAndGuestBound(t *testing.T) {
	scope, err := validateScope(scopeFixture())
	if err != nil {
		t.Fatal(err)
	}
	d := &ownedGuestLifecycle{scope: scope, witnesses: map[string]*nativeWitnessMemory{}}
	in := generated.NativeStepRequest{ScopeDigest: scope.digest, ControllerInstanceID: scope.value.ControllerInstanceID, GuestID: "controller", ScenarioID: "native-credential-lifecycle", Operation: "witness", RunID: "first-run"}
	sample := func(outcome, key string) generated.NativeStepResult {
		return generated.NativeStepResult{Binding: in, Status: "completed", SSH: &generated.NativeSshObservation{HostKeyVerified: true, Outcomes: []string{outcome}, PublicKeyDigest: hostaction.Digest(key)}}
	}
	if d.captureWitness(in, sample("allowed", "previous")) != nil {
		t.Fatal("initial denied")
	}
	in.RunID = "second-run"
	if d.captureWitness(in, sample("denied", "different")) == nil {
		t.Fatal("different old key accepted")
	}
	if d.captureWitness(in, sample("denied", "previous")) != nil {
		t.Fatal("old denial rejected")
	}
	in.RunID = "third-run"
	if d.captureWitness(in, sample("allowed", "previous")) == nil {
		t.Fatal("unchanged key accepted")
	}
	if d.captureWitness(in, sample("allowed", "current")) != nil {
		t.Fatal("current rejected")
	}
	b := generated.NativeObservationBinding{ScopeDigest: scope.digest, ControllerInstanceID: scope.value.ControllerInstanceID, GuestID: in.GuestID, ScenarioID: in.ScenarioID, RunID: "final-run"}
	out := generated.NativeObservation{}
	d.attachWitness(b, &out)
	if out.Credential == nil {
		t.Fatal("complete lifecycle absent")
	}
	for _, alter := range []func(*generated.NativeObservationBinding){func(b *generated.NativeObservationBinding) { b.RecoveryEpoch++ }, func(b *generated.NativeObservationBinding) { b.GuestID = "subject" }} {
		changed := b
		alter(&changed)
		out = generated.NativeObservation{}
		d.attachWitness(changed, &out)
		if out.Credential != nil {
			t.Fatal("cross-boundary sample reuse")
		}
	}
	if d.captureWitness(in, sample("allowed", "current")) == nil {
		t.Fatal("completed sequence overwritten")
	}
}
