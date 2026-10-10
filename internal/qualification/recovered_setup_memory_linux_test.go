//go:build linux

package qualification

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"strings"
	"testing"
)

func recoveredSetupMemoryFixture(t *testing.T) (*ownedGuestLifecycle, generated.NativeObservationBinding) {
	t.Helper()
	value := scopeFixture()
	replacement := value.Guests[1]
	replacement.GuestID, replacement.HostID, replacement.InstanceID, replacement.Role = "replacement", "replacement-host", "replacement-guest", "replacement"
	replacement.HostIdentityDigest, replacement.SSHHostKeyDigest = hostaction.Digest("replacement identity"), hostaction.Digest("replacement ssh")
	replacement.MachineID, replacement.CPUs, replacement.MemoryBytes, replacement.DiskBytes = strings.Repeat("b", 32), 1, GiB, 10*GiB
	value.Guests = append(value.Guests, replacement)
	scope, err := validateScope(value)
	if err != nil {
		t.Fatal(err)
	}
	original := scope.guests["controller"]
	fixture := generated.NativeSlackFixtureScope{RunControlSetup: true, ControlServiceUID: value.ControlServiceUID, ControlServiceGID: value.ControlServiceGID, IssuedAt: value.IssuedAt, ExpiresAt: value.ExpiresAt, GuestInstanceID: original.InstanceID, HostIdentityDigest: original.HostIdentityDigest, SSHHostKeyDigest: original.SSHHostKeyDigest, SourceCommit: value.SourceCommit, ExecutableDigest: value.ExecutableDigest}
	witness := generated.NativeControlSetupWitness{FixtureScope: fixture, ScopeDigest: hostaction.Digest(fixture), InstanceID: value.ControllerInstanceID, RecoveryEpoch: 0}
	restore := generated.RestoreBinding{PriorInstanceID: value.ControllerInstanceID, NewInstanceID: "restored-instance", PriorRecoveryEpoch: 0, NextRecoveryEpoch: 1, ReplacementHostID: replacement.HostID}
	identity := generated.NativeControllerIdentity{HostID: replacement.HostID, HostIdentityDigest: replacement.HostIdentityDigest, HostMachineID: replacement.MachineID, ControllerInstanceID: restore.NewInstanceID, ScopeDigest: scope.digest, ExecutableDigest: value.ExecutableDigest}
	driver := &ownedGuestLifecycle{scope: scope, activeController: "replacement", recoveredBinding: &restore, recoveredController: &identity, witnesses: map[string]*nativeWitnessMemory{}}
	request := generated.NativeStepRequest{Operation: "witness", GuestID: "controller", ScenarioID: "control-setup", ScopeDigest: scope.digest, ControllerInstanceID: value.ControllerInstanceID, RecoveryEpoch: 1, PlanDigest: hostaction.Digest("replacement role plan"), PlanID: "plan", RunID: "run", StepID: "step", LeaseID: "lease"}
	if err := driver.captureWitness(request, generated.NativeStepResult{Binding: request, Status: "completed", ControlSetup: &witness}); err != nil {
		t.Fatal(err)
	}
	binding := generated.NativeObservationBinding{GuestID: "replacement", ScenarioID: request.ScenarioID, ScopeDigest: request.ScopeDigest, ControllerInstanceID: request.ControllerInstanceID, RecoveryEpoch: request.RecoveryEpoch, PlanDigest: request.PlanDigest, PlanID: request.PlanID, RunID: request.RunID, StepID: request.StepID, LeaseID: request.LeaseID}
	return driver, binding
}

func TestRecoveredSetupMemoryKeepsOriginalWitnessForVerifiedReplacement(t *testing.T) {
	driver, binding := recoveredSetupMemoryFixture(t)
	var observed generated.NativeObservation
	driver.attachWitness(binding, &observed)
	if observed.ControlSetup == nil || observed.ControlSetup.FixtureScope.GuestInstanceID != driver.scope.guests["controller"].InstanceID {
		t.Fatal("original setup lineage dropped for the verified replacement producer")
	}
	for _, w := range driver.witnesses {
		w.volume = &generated.NativeVolumeSealWitness{HeaderBeforeDigest: hostaction.Digest("unrelated volume")}
	}
	observed = generated.NativeObservation{}
	driver.attachWitness(binding, &observed)
	if observed.ControlSetup == nil || observed.VolumeSeal != nil {
		t.Fatal("unrelated witness crossed the recovery join")
	}
	for _, variant := range []string{"missing-restore", "missing-selection", "inactive-replacement", "wrong-host", "wrong-instance", "wrong-epoch", "wrong-origin", "wrong-source", "wrong-original-guest", "wrong-lease", "wrong-plan", "wrong-scenario", "wrong-selection-host", "wrong-selection-machine", "wrong-selection-scope", "wrong-selection-executable", "empty-new-instance", "bad-epoch-increment", "wrong-original-identity", "wrong-original-ssh", "wrong-window", "wrong-owner", "bad-fixture-digest", "unrelated-only"} {
		t.Run(variant, func(t *testing.T) {
			d, b := recoveredSetupMemoryFixture(t)
			for _, w := range d.witnesses {
				switch variant {
				case "missing-restore":
					d.recoveredBinding = nil
				case "missing-selection":
					d.recoveredController = nil
				case "inactive-replacement":
					d.activeController = "subject"
				case "wrong-host":
					d.recoveredBinding.ReplacementHostID = "outside"
				case "wrong-instance":
					d.recoveredController.ControllerInstanceID = "outside"
				case "wrong-epoch":
					b.RecoveryEpoch = 0
				case "wrong-origin":
					d.recoveredBinding.PriorInstanceID = "outside"
				case "wrong-source":
					w.setup.FixtureScope.SourceCommit = strings.Repeat("f", 40)
					w.setup.ScopeDigest = hostaction.Digest(w.setup.FixtureScope)
				case "wrong-original-guest":
					w.guest = "subject"
				case "wrong-lease":
					b.LeaseID = "other"
				case "wrong-plan":
					b.PlanDigest = hostaction.Digest("other")
				case "wrong-scenario":
					b.ScenarioID = "control-handoff"
				case "wrong-selection-host":
					d.recoveredController.HostID = "outside"
				case "wrong-selection-machine":
					d.recoveredController.HostMachineID = strings.Repeat("c", 32)
				case "wrong-selection-scope":
					d.recoveredController.ScopeDigest = hostaction.Digest("outside")
				case "wrong-selection-executable":
					d.recoveredController.ExecutableDigest = hostaction.Digest("outside")
				case "empty-new-instance":
					d.recoveredBinding.NewInstanceID = ""
				case "bad-epoch-increment":
					d.recoveredBinding.NextRecoveryEpoch = 2
				case "wrong-original-identity":
					w.setup.FixtureScope.HostIdentityDigest = hostaction.Digest("outside")
					w.setup.ScopeDigest = hostaction.Digest(w.setup.FixtureScope)
				case "wrong-original-ssh":
					w.setup.FixtureScope.SSHHostKeyDigest = hostaction.Digest("outside")
					w.setup.ScopeDigest = hostaction.Digest(w.setup.FixtureScope)
				case "wrong-window":
					w.setup.FixtureScope.ExpiresAt = w.setup.FixtureScope.IssuedAt
					w.setup.ScopeDigest = hostaction.Digest(w.setup.FixtureScope)
				case "wrong-owner":
					w.setup.FixtureScope.ControlServiceUID++
					w.setup.ScopeDigest = hostaction.Digest(w.setup.FixtureScope)
				case "bad-fixture-digest":
					w.setup.ScopeDigest = hostaction.Digest("outside")
				case "unrelated-only":
					w.setup = nil
					w.volume = &generated.NativeVolumeSealWitness{}

				}
			}
			var got generated.NativeObservation
			d.attachWitness(b, &got)
			if got.ControlSetup != nil {
				t.Fatal("unbound historical setup witness accepted")
			}
		})
	}
}
