//go:build linux

package qualification

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"testing"
)

func TestReplacementRestartRequiresRecoveredGuestAndPreservesFrozenOwnership(t *testing.T) {
	_, state := recoveryNegativeRequestFixture()
	s := scopeFixture()
	s.Guests[0].HostID = state.OldHostID
	s.Guests[0].HostIdentityDigest = state.OldIdentityDigest
	replacement := s.Guests[1]
	replacement.Role = "replacement"
	replacement.GuestID = "replacement"
	replacement.InstanceID = "replacement-instance"
	replacement.SSHHostKeyDigest = hostaction.Digest("replacement-key")
	replacement.HostID = state.NewHostID
	replacement.HostIdentityDigest = state.NewIdentityDigest
	replacement.CPUs = 1
	replacement.MemoryBytes = GiB
	s.Guests = append(s.Guests, replacement)
	scope, err := validateScope(s)
	if err != nil {
		t.Fatal(err)
	}
	d := &ownedGuestLifecycle{scope: scope, activeController: "controller", launches: map[string]generated.NativeGuestLaunch{"replacement": {QEMUPID: 101, QEMUStartTimeTicks: 100}}, replacement: &nativeReplacementMemory{state: &state}}
	step := generated.NativeStepRequest{ScopeDigest: scope.digest, ControllerInstanceID: s.ControllerInstanceID, ScenarioID: "replacement-recovery", GuestID: "replacement", RecoveryEpoch: 1, Operation: "reboot-native"}
	if d.beginReplacementRestart(step, "before") == nil {
		t.Fatal("unused replacement restart accepted as interruption")
	}
	d.activeController = "replacement"
	d.recoveredController = &generated.NativeControllerIdentity{ControllerInstanceID: "recovered"}
	d.recoveredBinding = &generated.RestoreBinding{NextRecoveryEpoch: 1}
	if d.beginReplacementRestart(step, "before") != nil {
		t.Fatal("recovered controller interruption refused")
	}
	if d.finishReplacementRestart(step, "before") == nil {
		t.Fatal("unchanged boot accepted")
	}
	d.launches["replacement"] = generated.NativeGuestLaunch{QEMUPID: 202, QEMUStartTimeTicks: 200}
	if d.finishReplacementRestart(step, "after") != nil {
		t.Fatal("actual changed launch rejected")
	}
	step.Operation = "prepare"
	after := state
	after.StateRevision++
	out := generated.NativeStepResult{Binding: step, Status: "completed", Preparation: &generated.NativePreparationResult{ReplacementState: &after}}
	mutated := after
	mutated.AliasBindings = append([]generated.HostReplacementAliasBinding{}, after.AliasBindings...)
	mutated.AliasBindings[0].OwnerHostID = "different"
	out.Preparation.ReplacementState = &mutated
	if d.captureReplacementOutput(step, out) == nil {
		t.Fatal("ownership changed across interruption")
	}
	out.Preparation.ReplacementState = &after
	if d.captureReplacementOutput(step, out) != nil {
		t.Fatal("unchanged frozen state rejected")
	}
	if d.replacement.restart != nil || d.replacement.witness == nil || len(d.replacement.witness.Attempts) != 1 || d.replacement.witness.Attempts[0].Kind != "interrupted-transition" {
		t.Fatal("missing measured interruption")
	}
	if appendReplacementAttempt(d.replacement, d.replacement.witness.Attempts[0]) == nil {
		t.Fatal("duplicate attempt accepted")
	}
	// Routing alone cannot expose an incomplete negative witness or old epoch.
	b := generated.NativeObservationBinding{ScopeDigest: scope.digest, ControllerInstanceID: s.ControllerInstanceID, GuestID: "replacement", ScenarioID: "replacement-recovery", RecoveryEpoch: 1}
	observed := generated.NativeObservation{}
	d.attachWitness(b, &observed)
	if observed.ReplacementRecovery != nil {
		t.Fatal("incomplete recovery scenarios exposed")
	}
}
