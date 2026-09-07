package metadata

import "strings"

const (
	runResultSchemaID   = "vegastack-labs.dev/run-result"
	resultErrorSchemaID = "vegastack-labs.dev/result-error"
)

var requiredErrors = []ErrorDefinition{
	{Code: "APPROVAL_REQUIRED", ExitCode: 4},
	{Code: "AUTHENTICATION_REQUIRED", ExitCode: 3},
	{Code: "AUTHORIZATION_DENIED", ExitCode: 4},
	{Code: "DEPENDENCY_UNAVAILABLE", ExitCode: 6},
	{Code: "EVIDENCE_EXPIRED", ExitCode: 5},
	{Code: "EVIDENCE_INVALID", ExitCode: 2},
	{Code: "EXECUTION_FAILED", ExitCode: 7},
	{Code: "EXECUTION_PARTIAL", ExitCode: 7},
	{Code: "GATE_BLOCKED", ExitCode: 6},
	{Code: "INPUT_INVALID", ExitCode: 2},
	{Code: "INTEGRITY_FAILURE", ExitCode: 8},
	{Code: "INTERRUPTED", ExitCode: 9},
	{Code: "MIGRATION_BLOCKED", ExitCode: 8},
	{Code: "PLAN_STALE", ExitCode: 5},
	{Code: "PREREQUISITE_BLOCKED", ExitCode: 6},
	{Code: "RECOVERY_EPOCH_MISMATCH", ExitCode: 5},
	{Code: "RECOVERY_REQUIRED", ExitCode: 7},
	{Code: "SCHEMA_UNSUPPORTED", ExitCode: 2},
	{Code: "SESSION_EXPIRED", ExitCode: 3},
	{Code: "STATE_CONFLICT", ExitCode: 5},
	{Code: "TARGET_UNREACHABLE", ExitCode: 6},
	{Code: "UNSUPPORTED_PLATFORM", ExitCode: 2},
	{Code: "VERSION_INCOMPATIBLE", ExitCode: 5},
}

var requiredExits = []ExitDefinition{
	{Code: 0, Meaning: "read, plan, or apply completed successfully; inspect changed for a no-op"},
	{Code: 2, Meaning: "command usage, parse, or schema validation failed before authorization"},
	{Code: 3, Meaning: "caller could not be authenticated or the session expired or was revoked"},
	{Code: 4, Meaning: "authenticated caller lacks scope or required acknowledgement"},
	{Code: 5, Meaning: "state, plan, evidence, recovery epoch, or client/server version conflict"},
	{Code: 6, Meaning: "prerequisite, gate, target, credential reference, or dependency is unavailable"},
	{Code: 7, Meaning: "execution began and failed, stopped partial, or requires recovery"},
	{Code: 8, Meaning: "database, audit, or migration integrity failure"},
	{Code: 9, Meaning: "caller cancellation or interruption reached a declared safe boundary"},
}

type plannedCommand struct {
	path    string
	phase   string
	summary string
}

var plannedCommands = []plannedCommand{
	{path: "status", phase: "2", summary: "Show the current platform summary."},
	{path: "doctor", phase: "2", summary: "Diagnose one actionable platform invariant at a time."},
	{path: "plan", phase: "4", summary: "Create an immutable plan from an inert change."},
	{path: "apply", phase: "4", summary: "Execute one current, authorized immutable plan."},
	{path: "audit", phase: "5", summary: "Inspect sanitized audit history."},
	{path: "inventory import", phase: "2", summary: "Import typed inventory as an inert change."},
	{path: "inventory export", phase: "2", summary: "Export authorized inventory data."},
	{path: "inventory diff", phase: "2", summary: "Compare declared and supplied inventory."},
	{path: "gate list", phase: "5", summary: "List applicable implementation gates."},
	{path: "gate inspect", phase: "5", summary: "Inspect one gate and its evidence requirements."},
	{path: "gate check", phase: "5", summary: "Evaluate applicable gates without changing infrastructure."},
	{path: "gate evidence", phase: "5", summary: "Validate evidence and create an inert evidence change."},
	{path: "node discover", phase: "6", summary: "Discover a candidate managed node."},
	{path: "node add", phase: "6", summary: "Create an inert managed-node change."},
	{path: "node inspect", phase: "6", summary: "Inspect a managed node."},
	{path: "node nominate", phase: "6", summary: "Create an inert role-nomination change."},
	{path: "node quarantine", phase: "6", summary: "Create an inert node-quarantine change."},
	{path: "node replace", phase: "6", summary: "Create an inert node-replacement change."},
	{path: "user onboard", phase: "7", summary: "Create an inert user-onboarding change."},
	{path: "user offboard", phase: "7", summary: "Create an inert user-offboarding change."},
	{path: "user suspend", phase: "7", summary: "Create an inert user-suspension change."},
	{path: "user resume", phase: "7", summary: "Create an inert user-resumption change."},
	{path: "device request", phase: "7", summary: "Create an inert device-enrollment request."},
	{path: "device approve", phase: "7", summary: "Create an inert device-approval change."},
	{path: "device revoke", phase: "7", summary: "Create an inert device-revocation change."},
	{path: "service plan", phase: "8", summary: "Create an inert service change and request its plan."},
	{path: "service deploy", phase: "8", summary: "Create an inert service-deployment change."},
	{path: "service rollback", phase: "8", summary: "Create an inert service-rollback change."},
	{path: "backup status", phase: "5", summary: "Inspect backup status."},
	{path: "backup run", phase: "5", summary: "Run one exact approved backup policy."},
	{path: "backup verify", phase: "5", summary: "Verify a declared backup."},
	{path: "restore plan", phase: "5", summary: "Create an immutable restore plan."},
	{path: "restore run", phase: "5", summary: "Run one authorized restore plan."},
	{path: "restore verify", phase: "5", summary: "Verify a completed restore."},
	{path: "maintenance plan", phase: "10", summary: "Create an immutable maintenance plan."},
	{path: "maintenance run", phase: "10", summary: "Run one authorized maintenance plan."},
	{path: "connect", phase: "7", summary: "Open a constrained connection to an authorized node endpoint."},
	{path: "control-plane plan", phase: "6", summary: "Create an immutable control-plane change plan."},
	{path: "control-plane verify", phase: "6", summary: "Verify control-plane health and authority."},
	{path: "control-plane recover", phase: "6", summary: "Create an inert control-plane recovery change."},
	{path: "database status", phase: "2", summary: "Inspect control-database status."},
	{path: "database backup", phase: "5", summary: "Create a verified control-database backup."},
	{path: "database verify", phase: "5", summary: "Verify control-database integrity or backup content."},
	{path: "database restore", phase: "5", summary: "Create an inert control-database restore change."},
	{path: "database export", phase: "5", summary: "Export authorized sanitized control data."},
	{path: "server run", phase: "2", summary: "Run the persistent control service in the foreground."},
	{path: "server status", phase: "2", summary: "Query control-service health."},
	{path: "release inspect", phase: "11", summary: "Inspect a release manifest and compatibility."},
	{path: "release verify", phase: "11", summary: "Verify release identity, signature, and digest."},
}

func Current() Registry {
	commands := []CommandDefinition{
		foundationCommand("help", "Show generated command help.", []ExampleDefinition{
			{Summary: "Show all generated command help.", Arguments: []string{"help"}},
		}),
		foundationCommand("version", "Show the vsk-labs build and contract version.", []ExampleDefinition{
			{Summary: "Show version information as JSON.", Arguments: []string{"version", "--output", "json"}},
		}),
	}
	for _, command := range plannedCommands {
		commands = append(commands, CommandDefinition{
			Path:         strings.Fields(command.path),
			Summary:      command.summary,
			Availability: AvailabilityPlanned,
			OwnerPhase:   command.phase,
			Risk:         RiskUnassigned,
		})
	}

	return Registry{
		SchemaVersion: "1.0.0",
		Commands:      commands,
		Errors:        append([]ErrorDefinition(nil), requiredErrors...),
		Exits:         append([]ExitDefinition(nil), requiredExits...),
		Schemas:       currentSchemas(),
	}
}

func foundationCommand(name, summary string, examples []ExampleDefinition) CommandDefinition {
	return CommandDefinition{
		Path:         []string{name},
		Summary:      summary,
		Availability: AvailabilityAvailable,
		OwnerPhase:   "1",
		Risk:         RiskReadOnly,
		Flags: []FlagDefinition{
			{
				Name:      "--output",
				ValueName: "format",
				Summary:   "Select human or versioned JSON output.",
				Enum:      []string{"human", "json"},
			},
		},
		ResultSchema: runResultSchemaID,
		Examples:     examples,
	}
}

func currentSchemas() []SchemaDefinition {
	return []SchemaDefinition{
		{
			ID:      resultErrorSchemaID,
			Version: "1.0.0",
			Fields: []FieldDefinition{
				{JSONName: "code", GoName: "Code", Kind: ValueString, Required: true},
				{JSONName: "target", GoName: "Target", Kind: ValueString, Required: true},
				{JSONName: "retryable", GoName: "Retryable", Kind: ValueBoolean, Required: true},
			},
		},
		{
			ID:      runResultSchemaID,
			Version: "1.0.0",
			Fields: []FieldDefinition{
				{JSONName: "schema", GoName: "Schema", Kind: ValueString, Required: true, Enum: []string{runResultSchemaID}},
				{JSONName: "schemaVersion", GoName: "SchemaVersion", Kind: ValueString, Required: true, Enum: []string{"1.0.0"}},
				{JSONName: "toolVersion", GoName: "ToolVersion", Kind: ValueString, Required: true},
				{JSONName: "command", GoName: "Command", Kind: ValueString, Required: true},
				{JSONName: "requestId", GoName: "RequestID", Kind: ValueString, Required: true},
				{JSONName: "runId", GoName: "RunID", Kind: ValueString, Required: true, Nullable: true},
				{JSONName: "status", GoName: "Status", Kind: ValueString, Required: true, Enum: []string{"blocked", "cancelled", "failed", "interrupted", "partial", "succeeded"}},
				{JSONName: "changed", GoName: "Changed", Kind: ValueBoolean, Required: true},
				{JSONName: "recoveryEpoch", GoName: "RecoveryEpoch", Kind: ValueInteger, Required: true},
				{JSONName: "stateRevision", GoName: "StateRevision", Kind: ValueInteger, Required: true},
				{JSONName: "snapshotDigest", GoName: "SnapshotDigest", Kind: ValueString, Required: true, Nullable: true},
				{JSONName: "releaseBuildId", GoName: "ReleaseBuildID", Kind: ValueString, Required: true},
				{JSONName: "sourceRevision", GoName: "SourceRevision", Kind: ValueString, Required: true, Nullable: true},
				{JSONName: "planId", GoName: "PlanID", Kind: ValueString, Required: true, Nullable: true},
				{JSONName: "errors", GoName: "Errors", Kind: ValueArray, Required: true, ItemRef: resultErrorSchemaID},
				{JSONName: "data", GoName: "Data", Kind: ValueObject, Required: true, AdditionalProperties: true},
			},
		},
	}
}

func commandName(path []string) string {
	return strings.Join(path, " ")
}

func ExitCodeFor(codes []string) (int, error) {
	if len(codes) == 0 {
		return 0, validationError("ERROR_SEQUENCE_EMPTY", "errors")
	}
	for _, definition := range requiredErrors {
		if definition.Code == codes[0] {
			return definition.ExitCode, nil
		}
	}
	return 0, validationError("ERROR_CODE_UNKNOWN", "errors[0]")
}
