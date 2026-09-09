package metadata

import (
	"encoding/json"
	"reflect"
	"regexp"
	"testing"
)

func TestPhaseTwoReadEndpointsAreGeneratedAndDraftScoped(t *testing.T) {
	registry := Current()
	byID := make(map[string]EndpointDefinition, len(registry.Endpoints))
	for _, endpoint := range registry.Endpoints {
		byID[endpoint.ID] = endpoint
		if endpoint.Path == "/api/v1/assets" || endpoint.Path == "/api/v1/nodes" {
			t.Fatalf("authoritative-looking endpoint generated: %#v", endpoint)
		}
	}
	got := byID["api.v1.inventory-draft-assets.list"]
	if got.Method != "GET" || got.Path != "/api/v1/inventory-drafts/{draftId}/revisions/{revision}/assets" || got.Stream != StreamFinite {
		t.Fatalf("asset endpoint = %#v", got)
	}
	events := byID["api.v1.events.stream"]
	if events.Path != "/api/v1/events" || events.Stream != StreamSSE || events.DataSchema != apiAuditEventDataSchemaID {
		t.Fatalf("events endpoint = %#v", events)
	}
}

func TestInventoryDraftContractsAreStrictAndProviderNeutral(t *testing.T) {
	t.Parallel()

	registry := Current()
	if registry.SchemaVersion != "1.4.0" {
		t.Fatalf("SchemaVersion = %q, want 1.4.0", registry.SchemaVersion)
	}
	input := schemaByID(t, registry, "vegastack-labs.dev/inventory-draft-input")
	result := schemaByID(t, registry, "vegastack-labs.dev/inventory-import-data")
	if input.Version != "1.0.0" || result.Version != "1.0.0" {
		t.Fatalf("inventory versions = (%q, %q)", input.Version, result.Version)
	}
	seenEventID := false
	for _, field := range result.Fields {
		seenEventID = seenEventID || field.JSONName == "eventId"
	}
	if !seenEventID {
		t.Fatal("inventory import result does not expose its durable event ID")
	}
	encoded, err := json.Marshal(struct {
		Input  []FieldDefinition
		Result []FieldDefinition
	}{input.Fields, result.Fields})
	if err != nil {
		t.Fatal(err)
	}
	forbidden := regexp.MustCompile(`(?i)(labs\.vegastack|google|sheet|provider|vsk-node|spreadsheet|columnName)`)
	if forbidden.Match(encoded) {
		t.Fatalf("inventory contract leaks deployment/adapter vocabulary: %s", encoded)
	}
}

func TestAuditContractsAreClosedBoundedAndSecretFree(t *testing.T) {
	t.Parallel()

	registry := Current()
	if registry.SchemaVersion != "1.4.0" {
		t.Fatalf("SchemaVersion = %q, want 1.4.0", registry.SchemaVersion)
	}
	event := schemaByID(t, registry, "vegastack-labs.dev/audit-event")
	outbox := schemaByID(t, registry, "vegastack-labs.dev/outbox-record-data")
	if event.ArtifactPath != "schemas/v1/audit-event.schema.json" || outbox.ArtifactPath != "schemas/v1/outbox-record-data.schema.json" {
		t.Fatalf("audit artifacts = %q, %q", event.ArtifactPath, outbox.ArtifactPath)
	}
	encoded, err := json.Marshal([][]FieldDefinition{event.Fields, outbox.Fields})
	if err != nil {
		t.Fatal(err)
	}
	forbidden := regexp.MustCompile(`(?i)(raw|path|prompt|secret|providerResponse|lastError[^C])`)
	if forbidden.Match(encoded) {
		t.Fatalf("audit contract contains unsafe/open field: %s", encoded)
	}
	for _, schema := range []SchemaDefinition{event, outbox} {
		for _, field := range schema.Fields {
			if !field.Required || field.AdditionalProperties {
				t.Fatalf("field %s.%s is not closed/required", schema.ID, field.JSONName)
			}
		}
	}
}

func schemaByID(t *testing.T, registry Registry, id string) SchemaDefinition {
	t.Helper()
	for _, schema := range registry.Schemas {
		if schema.ID == id {
			return schema
		}
	}
	t.Fatalf("schema %q is missing", id)
	return SchemaDefinition{}
}

func TestCurrentHasFoundationAndDocumentedCommands(t *testing.T) {
	t.Parallel()

	registry := Current()
	if registry.SchemaVersion != "1.4.0" {
		t.Fatalf("SchemaVersion = %q, want 1.4.0", registry.SchemaVersion)
	}

	wantAvailable := map[string]bool{"help": false, "release inspect": false, "release verify": false, "server run": false, "server status": false, "version": false}
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
			if command.Risk != RiskUnassigned || len(command.Flags) != 0 || command.RequestSchema != "" || command.ResultSchema != "" || command.DataSchema != "" || len(command.Examples) != 0 {
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

func TestDatabaseStatusDataIsClosedAndSanitized(t *testing.T) {
	t.Parallel()

	registry := Current()
	var got *SchemaDefinition
	for i := range registry.Schemas {
		if registry.Schemas[i].ID == "vegastack-labs.dev/database-status-data" {
			got = &registry.Schemas[i]
		}
	}
	if got == nil || got.ArtifactPath != "schemas/v1/database-status-data.schema.json" {
		t.Fatal("database status data schema is missing")
	}
	want := []string{"mode", "schemaVersion", "sqliteVersion", "mutationEnabled", "recoveryPending", "integrityStatus", "lastIntegrityCheckAt", "safeModeReason"}
	names := make([]string, 0, len(got.Fields))
	for _, field := range got.Fields {
		names = append(names, field.JSONName)
	}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("fields = %v, want %v", names, want)
	}
}

func TestServerCommandsFreezePhaseTwoContracts(t *testing.T) {
	t.Parallel()

	registry := Current()
	run := commandByName(t, registry, "server run")
	status := commandByName(t, registry, "server status")
	if run.Availability != AvailabilityAvailable || run.Risk != RiskLocalService || run.OwnerPhase != "2" {
		t.Fatalf("server run contract = %#v", run)
	}
	if status.Availability != AvailabilityAvailable || status.Risk != RiskReadOnly || status.OwnerPhase != "2" || status.DataSchema != serverStatusDataSchemaID {
		t.Fatalf("server status contract = %#v", status)
	}
	assertFlag(t, run, "--config", FlagValue, true, false)
	assertFlag(t, status, "--config", FlagValue, true, false)
}

func TestReleaseCommandsAreGeneratedPhaseOneContracts(t *testing.T) {
	t.Parallel()

	registry := Current()
	inspect := commandByName(t, registry, "release inspect")
	verify := commandByName(t, registry, "release verify")
	if inspect.Availability != AvailabilityAvailable || verify.Availability != AvailabilityAvailable {
		t.Fatal("release commands must be available")
	}
	if inspect.OwnerPhase != "1" || verify.OwnerPhase != "1" {
		t.Fatal("release commands must be owned by Phase 1")
	}
	if inspect.DataSchema != releaseInspectDataSchemaID || verify.DataSchema != releaseVerifyDataSchemaID {
		t.Fatal("release commands must name generated data schemas")
	}
	assertFlag(t, inspect, "--manifest", FlagValue, true, false)
	assertFlag(t, verify, "--manifest", FlagValue, true, false)
	assertFlag(t, verify, "--policy", FlagValue, true, false)
	assertFlag(t, verify, "--asset", FlagValue, false, true)
	assertFlag(t, verify, "--all", FlagSwitch, false, false)
}

func commandByName(t *testing.T, registry Registry, name string) CommandDefinition {
	t.Helper()
	for _, command := range registry.Commands {
		if commandName(command.Path) == name {
			return command
		}
	}
	t.Fatalf("command %q is missing", name)
	return CommandDefinition{}
}

func assertFlag(t *testing.T, command CommandDefinition, name string, kind FlagKind, required, repeatable bool) {
	t.Helper()
	for _, flag := range command.Flags {
		if flag.Name == name {
			if flag.Kind != kind || flag.Required != required || flag.Repeatable != repeatable {
				t.Fatalf("%s flag %s = %#v", commandName(command.Path), name, flag)
			}
			return
		}
	}
	t.Fatalf("%s flag %s is missing", commandName(command.Path), name)
}

func TestFoundationCommandsExposeSchemaMajor(t *testing.T) {
	t.Parallel()

	for _, command := range Current().Commands {
		if command.Availability != AvailabilityAvailable {
			continue
		}
		if !hasFlag(command.Flags, "--schema-version", "major", []string{"1"}) {
			t.Fatalf("%v does not expose generated schema-major selection", command.Path)
		}
	}
}

func hasFlag(flags []FlagDefinition, name, valueName string, enum []string) bool {
	for _, flag := range flags {
		if flag.Name == name && flag.ValueName == valueName && reflect.DeepEqual(flag.Enum, enum) {
			return true
		}
	}
	return false
}

func TestCurrentErrorExitMapping(t *testing.T) {
	t.Parallel()

	want := map[string]int{
		"INPUT_INVALID": 2, "SCHEMA_UNSUPPORTED": 2, "UNSUPPORTED_PLATFORM": 2, "EVIDENCE_INVALID": 2,
		"AUTHENTICATION_REQUIRED": 3, "SESSION_EXPIRED": 3,
		"AUTHORIZATION_DENIED": 4, "APPROVAL_REQUIRED": 4,
		"STATE_CONFLICT": 5, "PLAN_STALE": 5, "EVIDENCE_EXPIRED": 5, "RECOVERY_EPOCH_MISMATCH": 5, "VERSION_INCOMPATIBLE": 5,
		"PREREQUISITE_BLOCKED": 6, "GATE_BLOCKED": 6, "TARGET_UNREACHABLE": 6, "DEPENDENCY_UNAVAILABLE": 6, "RESOURCE_NOT_FOUND": 6,
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
