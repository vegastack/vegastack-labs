package metadata

import (
	"reflect"
	"testing"
)

func TestCurrentHasFoundationAndDocumentedCommands(t *testing.T) {
	t.Parallel()

	registry := Current()
	if registry.SchemaVersion != "1.0.0" {
		t.Fatalf("SchemaVersion = %q, want 1.0.0", registry.SchemaVersion)
	}

	wantAvailable := map[string]bool{"help": false, "version": false}
	wantPlanned := map[string]string{
		"status": "2", "doctor": "2", "plan": "4", "apply": "4", "audit": "5",
		"inventory import": "2", "inventory export": "2", "inventory diff": "2",
		"gate list": "5", "gate inspect": "5", "gate check": "5", "gate evidence": "5",
		"node discover": "6", "node add": "6", "node inspect": "6", "node nominate": "6", "node quarantine": "6", "node replace": "6",
		"user onboard": "7", "user offboard": "7", "user suspend": "7", "user resume": "7",
		"device request": "7", "device approve": "7", "device revoke": "7",
		"service plan": "8", "service deploy": "8", "service rollback": "8",
		"backup status": "5", "backup run": "5", "backup verify": "5",
		"restore plan": "5", "restore run": "5", "restore verify": "5",
		"maintenance plan": "10", "maintenance run": "10", "connect": "7",
		"control-plane plan": "6", "control-plane verify": "6", "control-plane recover": "6",
		"database status": "2", "database backup": "5", "database verify": "5", "database restore": "5", "database export": "5",
		"server run": "2", "server status": "2", "release inspect": "11", "release verify": "11",
	}
	gotPlanned := make(map[string]string)
	for _, command := range registry.Commands {
		name := commandName(command.Path)
		switch command.Availability {
		case AvailabilityAvailable:
			if _, ok := wantAvailable[name]; !ok {
				t.Fatalf("unexpected available command %q", name)
			}
			wantAvailable[name] = true
		case AvailabilityPlanned:
			gotPlanned[name] = command.OwnerPhase
			if command.Risk != RiskUnassigned || len(command.Flags) != 0 || command.RequestSchema != "" || command.ResultSchema != "" || len(command.Examples) != 0 {
				t.Fatalf("planned command %q contains speculative contract detail", name)
			}
		default:
			t.Fatalf("command %q availability = %q", name, command.Availability)
		}
	}
	for name, found := range wantAvailable {
		if !found {
			t.Errorf("available command %q is missing", name)
		}
	}
	if !reflect.DeepEqual(gotPlanned, wantPlanned) {
		t.Fatalf("planned commands = %#v, want %#v", gotPlanned, wantPlanned)
	}
	if err := Validate(registry); err != nil {
		t.Fatalf("Validate(Current()) = %v", err)
	}
}

func TestCurrentErrorExitMapping(t *testing.T) {
	t.Parallel()

	want := map[string]int{
		"INPUT_INVALID": 2, "SCHEMA_UNSUPPORTED": 2, "UNSUPPORTED_PLATFORM": 2, "EVIDENCE_INVALID": 2,
		"AUTHENTICATION_REQUIRED": 3, "SESSION_EXPIRED": 3,
		"AUTHORIZATION_DENIED": 4, "APPROVAL_REQUIRED": 4,
		"STATE_CONFLICT": 5, "PLAN_STALE": 5, "EVIDENCE_EXPIRED": 5, "RECOVERY_EPOCH_MISMATCH": 5, "VERSION_INCOMPATIBLE": 5,
		"PREREQUISITE_BLOCKED": 6, "GATE_BLOCKED": 6, "TARGET_UNREACHABLE": 6, "DEPENDENCY_UNAVAILABLE": 6,
		"EXECUTION_FAILED": 7, "EXECUTION_PARTIAL": 7, "RECOVERY_REQUIRED": 7,
		"INTEGRITY_FAILURE": 8, "MIGRATION_BLOCKED": 8,
		"INTERRUPTED": 9,
	}

	got := make(map[string]int)
	for _, definition := range Current().Errors {
		got[definition.Code] = definition.ExitCode
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("error mapping = %#v, want %#v", got, want)
	}

	wantExits := []int{0, 2, 3, 4, 5, 6, 7, 8, 9}
	gotExits := make([]int, 0, len(Current().Exits))
	for _, definition := range Current().Exits {
		gotExits = append(gotExits, definition.Code)
	}
	if !reflect.DeepEqual(gotExits, wantExits) {
		t.Fatalf("exit codes = %v, want %v", gotExits, wantExits)
	}
}

func TestExitCodeForUsesFirstError(t *testing.T) {
	t.Parallel()

	got, err := ExitCodeFor([]string{"PLAN_STALE", "EXECUTION_FAILED"})
	if err != nil || got != 5 {
		t.Fatalf("ExitCodeFor() = (%d, %v), want (5, nil)", got, err)
	}
	if _, err := ExitCodeFor(nil); err == nil {
		t.Fatal("ExitCodeFor(nil) error = nil")
	}
	if _, err := ExitCodeFor([]string{"NOT_REGISTERED"}); err == nil {
		t.Fatal("ExitCodeFor(unknown) error = nil")
	}
}
