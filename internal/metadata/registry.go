package metadata

import "strings"

const (
	runResultSchemaID                       = "vegastack-labs.dev/run-result"
	resultErrorSchemaID                     = "vegastack-labs.dev/result-error"
	releaseManifestSchemaID                 = "vegastack-labs.dev/release-manifest"
	releaseAssetSchemaID                    = "vegastack-labs.dev/release-asset"
	releaseTrustPolicySchemaID              = "vegastack-labs.dev/release-trust-policy"
	releaseInspectDataSchemaID              = "vegastack-labs.dev/release-inspect-data"
	releaseVerifyDataSchemaID               = "vegastack-labs.dev/release-verify-data"
	releaseAssetVerificationSchemaID        = "vegastack-labs.dev/release-asset-verification"
	databaseStatusDataSchemaID              = "vegastack-labs.dev/database-status-data"
	localPrincipalBindingSchemaID           = "vegastack-labs.dev/local-principal-binding"
	remoteReadProfileSchemaID               = "vegastack-labs.dev/remote-read-profile"
	cloudflareAccessProfileSchemaID         = "vegastack-labs.dev/cloudflare-access-profile"
	serverProfileSchemaID                   = "vegastack-labs.dev/server-profile"
	serverStatusDataSchemaID                = "vegastack-labs.dev/server-status-data"
	stateExportKindCountSchemaID            = "vegastack-labs.dev/state-export-kind-count"
	stateExportDraftRefSchemaID             = "vegastack-labs.dev/state-export-draft-ref"
	stateExportSourceSchemaID               = "vegastack-labs.dev/state-export-source"
	stateExportDraftSchemaID                = "vegastack-labs.dev/state-export-draft"
	stateExportPayloadSchemaID              = "vegastack-labs.dev/inventory-draft-snapshot-payload"
	stateExportSignatureSchemaID            = "vegastack-labs.dev/inventory-draft-export-signature"
	stateExportDocumentSchemaID             = "vegastack-labs.dev/signed-inventory-draft-export"
	stateExportPointerSchemaID              = "vegastack-labs.dev/inventory-draft-export-pointer"
	inventoryDraftInputSchemaID             = "vegastack-labs.dev/inventory-draft-input"
	inventoryImportDataSchemaID             = "vegastack-labs.dev/inventory-import-data"
	inventoryDraftSourceSchemaID            = "vegastack-labs.dev/inventory-draft-source"
	inventoryDraftAssetSchemaID             = "vegastack-labs.dev/inventory-draft-asset"
	inventoryDraftIdentitySchemaID          = "vegastack-labs.dev/inventory-draft-identity"
	inventoryDraftNodeSchemaID              = "vegastack-labs.dev/inventory-draft-node"
	inventoryDraftAliasSchemaID             = "vegastack-labs.dev/inventory-draft-alias"
	inventoryDraftAddressSchemaID           = "vegastack-labs.dev/inventory-draft-address"
	inventoryDraftObservationSchemaID       = "vegastack-labs.dev/inventory-draft-observation"
	inventoryDraftHardwareFactSchemaID      = "vegastack-labs.dev/inventory-draft-hardware-fact"
	inventoryFieldProvenanceSchemaID        = "vegastack-labs.dev/inventory-field-provenance"
	inventoryFindingSchemaID                = "vegastack-labs.dev/inventory-finding"
	inventoryDraftCountsSchemaID            = "vegastack-labs.dev/inventory-draft-counts"
	auditEventSchemaID                      = "vegastack-labs.dev/audit-event"
	auditTargetSchemaID                     = "vegastack-labs.dev/audit-target"
	outboxRecordDataSchemaID                = "vegastack-labs.dev/outbox-record-data"
	apiPageQuerySchemaID                    = "vegastack-labs.dev/api-page-query"
	apiPageDataSchemaID                     = "vegastack-labs.dev/api-page-data"
	apiSummaryDataSchemaID                  = "vegastack-labs.dev/api-summary-data"
	apiSourceListQuerySchemaID              = "vegastack-labs.dev/api-source-list-query"
	apiSourceCountsDataSchemaID             = "vegastack-labs.dev/api-source-counts-data"
	apiSourceDataSchemaID                   = "vegastack-labs.dev/api-source-data"
	apiSourceListDataSchemaID               = "vegastack-labs.dev/api-source-list-data"
	apiInventoryDraftListDataSchemaID       = "vegastack-labs.dev/api-inventory-draft-list-data"
	apiInventoryDraftDataSchemaID           = "vegastack-labs.dev/api-inventory-draft-data"
	apiInventoryAssetListDataSchemaID       = "vegastack-labs.dev/api-inventory-asset-list-data"
	apiInventoryAssetDataSchemaID           = "vegastack-labs.dev/api-inventory-asset-data"
	apiInventoryNodeListDataSchemaID        = "vegastack-labs.dev/api-inventory-node-list-data"
	apiInventoryNodeDataSchemaID            = "vegastack-labs.dev/api-inventory-node-data"
	apiInventoryAliasListDataSchemaID       = "vegastack-labs.dev/api-inventory-alias-list-data"
	apiInventoryAliasDataSchemaID           = "vegastack-labs.dev/api-inventory-alias-data"
	apiInventoryObservationListDataSchemaID = "vegastack-labs.dev/api-inventory-observation-list-data"
	apiInventoryObservationDataSchemaID     = "vegastack-labs.dev/api-inventory-observation-data"
	apiAuditEventDataSchemaID               = "vegastack-labs.dev/api-audit-event-data"
	apiBrowserSessionRequestSchemaID        = "vegastack-labs.dev/api-browser-session-request"
	apiBrowserSessionDataSchemaID           = "vegastack-labs.dev/api-browser-session-data"
	inventoryDraftRefSchemaID               = "vegastack-labs.dev/inventory-draft-ref"
	inventoryImportRequestSchemaID          = "vegastack-labs.dev/inventory-import-request"
	inventoryDiffRequestSchemaID            = "vegastack-labs.dev/inventory-diff-request"
	inventoryFieldChangeSchemaID            = "vegastack-labs.dev/inventory-field-change"
	inventoryDiffRecordSchemaID             = "vegastack-labs.dev/inventory-diff-record"
	inventoryDiffCountsSchemaID             = "vegastack-labs.dev/inventory-diff-counts"
	inventoryDiffDataSchemaID               = "vegastack-labs.dev/inventory-diff-data"
	inventoryExportRequestSchemaID          = "vegastack-labs.dev/inventory-export-request"
	inventoryExportDataSchemaID             = "vegastack-labs.dev/inventory-export-data"
	declarationRevisionSchemaID             = "vegastack-labs.dev/declaration-revision"
	planSchemaID                            = "vegastack-labs.dev/plan"
	authorizationDecisionSchemaID           = "vegastack-labs.dev/authorization-decision"
	acknowledgementSchemaID                 = "vegastack-labs.dev/acknowledgement"
	runSchemaID                             = "vegastack-labs.dev/run"
	executorLeaseSchemaID                   = "vegastack-labs.dev/executor-lease"
	executionReceiptSchemaID                = "vegastack-labs.dev/execution-receipt"
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
	{Code: "RESOURCE_NOT_FOUND", ExitCode: 6},
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
}

func Current() Registry {
	commands := []CommandDefinition{
		foundationCommand("help", "Show generated command help.", []ExampleDefinition{
			{Summary: "Show all generated command help.", Arguments: []string{"help"}},
		}),
		foundationCommand("version", "Show the vsk-labs build and contract version.", []ExampleDefinition{
			{Summary: "Show version information as JSON.", Arguments: []string{"version", "--output", "json"}},
		}),
		releaseInspectCommand(),
		releaseVerifyCommand(),
		serverRunCommand(),
		serverStatusCommand(),
		platformStatusCommand(),
		databaseStatusCommand(),
		inventoryImportCommand(),
		inventoryDiffCommand(),
		inventoryExportCommand(),
	}
	for _, command := range plannedCommands {
		if command.path == "status" || command.path == "database status" || strings.HasPrefix(command.path, "inventory ") {
			continue
		}
		commands = append(commands, CommandDefinition{
			Path:         strings.Fields(command.path),
			Summary:      command.summary,
			Availability: AvailabilityPlanned,
			OwnerPhase:   command.phase,
			Risk:         RiskUnassigned,
		})
	}

	return Registry{
		SchemaVersion: "1.10.0",
		Commands:      commands,
		Endpoints:     append(readEndpoints(), phase4Endpoints()...),
		Errors:        append([]ErrorDefinition(nil), requiredErrors...),
		Exits:         append([]ExitDefinition(nil), requiredExits...),
		Schemas:       currentSchemas(),
		Lifecycle: LifecycleDefinition{
			PlanValiditySeconds:    30 * 60,
			LeaseDurationSeconds:   60,
			ExecutorCheckInSeconds: 20,
			RunTransitions: []TransitionDefinition{
				{From: "queued", To: "running"}, {From: "queued", To: "cancelled"},
				{From: "running", To: "succeeded"}, {From: "running", To: "failed"}, {From: "running", To: "partial"}, {From: "running", To: "interrupted"},
				{From: "interrupted", To: "running"}, {From: "interrupted", To: "cancelled"},
			},
		},
	}
}

func readEndpoints() []EndpointDefinition {
	finite := func(id, path, data string) EndpointDefinition {
		return EndpointDefinition{ID: id, Method: "GET", Path: path, Availability: AvailabilityAvailable, OwnerPhase: "2", DataSchema: data, Stream: StreamFinite, Audiences: []EndpointAudience{AudienceBrowser, AudienceOperator}}
	}
	list := func(id, path, data string) EndpointDefinition {
		value := finite(id, path, data)
		value.QuerySchema = apiPageQuerySchemaID
		return value
	}
	base := "/api/v1/inventory-drafts/{draftId}/revisions/{revision}"
	return []EndpointDefinition{
		finite("api.v1.health.get", "/api/v1/health", serverStatusDataSchemaID),
		finite("api.v1.database-status.get", "/api/v1/database/status", databaseStatusDataSchemaID),
		finite("api.v1.summary.get", "/api/v1/summary", apiSummaryDataSchemaID),
		{ID: "api.v1.sources.list", Method: "GET", Path: "/api/v1/sources", Availability: AvailabilityAvailable, OwnerPhase: "3", QuerySchema: apiSourceListQuerySchemaID, DataSchema: apiSourceListDataSchemaID, Stream: StreamFinite, Audiences: []EndpointAudience{AudienceBrowser, AudienceOperator}},
		list("api.v1.inventory-drafts.list", "/api/v1/inventory-drafts", apiInventoryDraftListDataSchemaID),
		finite("api.v1.inventory-drafts.get", base, apiInventoryDraftDataSchemaID),
		list("api.v1.inventory-draft-assets.list", base+"/assets", apiInventoryAssetListDataSchemaID),
		finite("api.v1.inventory-draft-assets.get", base+"/assets/{recordId}", apiInventoryAssetDataSchemaID),
		list("api.v1.inventory-draft-nodes.list", base+"/nodes", apiInventoryNodeListDataSchemaID),
		finite("api.v1.inventory-draft-nodes.get", base+"/nodes/{recordId}", apiInventoryNodeDataSchemaID),
		list("api.v1.inventory-draft-aliases.list", base+"/aliases", apiInventoryAliasListDataSchemaID),
		finite("api.v1.inventory-draft-aliases.get", base+"/aliases/{recordId}", apiInventoryAliasDataSchemaID),
		list("api.v1.inventory-draft-observations.list", base+"/observations", apiInventoryObservationListDataSchemaID),
		finite("api.v1.inventory-draft-observations.get", base+"/observations/{recordId}", apiInventoryObservationDataSchemaID),
		{ID: "api.v1.events.stream", Method: "GET", Path: "/api/v1/events", Availability: AvailabilityAvailable, OwnerPhase: "2", DataSchema: apiAuditEventDataSchemaID, Stream: StreamSSE, Audiences: []EndpointAudience{AudienceBrowser, AudienceOperator}},
		{ID: "api.v1.inventory-drafts.import", Method: "POST", Path: "/api/v1/inventory-drafts/import", Availability: AvailabilityAvailable, OwnerPhase: "2", RequestSchema: inventoryImportRequestSchemaID, DataSchema: inventoryImportDataSchemaID, Stream: StreamFinite, Audiences: []EndpointAudience{AudienceOperator}},
		{ID: "api.v1.inventory-diffs.create", Method: "POST", Path: "/api/v1/inventory-diffs", Availability: AvailabilityAvailable, OwnerPhase: "2", RequestSchema: inventoryDiffRequestSchemaID, DataSchema: inventoryDiffDataSchemaID, Stream: StreamFinite, Audiences: []EndpointAudience{AudienceOperator}},
		{ID: "api.v1.inventory-exports.create", Method: "POST", Path: "/api/v1/inventory-exports", Availability: AvailabilityAvailable, OwnerPhase: "2", RequestSchema: inventoryExportRequestSchemaID, DataSchema: inventoryExportDataSchemaID, Stream: StreamFinite, Audiences: []EndpointAudience{AudienceOperator}},
		{ID: "api.v1.session.create", Method: "POST", Path: "/api/v1/session", Availability: AvailabilityAvailable, OwnerPhase: "3", RequestSchema: apiBrowserSessionRequestSchemaID, DataSchema: apiBrowserSessionDataSchemaID, Stream: StreamFinite, Audiences: []EndpointAudience{AudienceBrowser}},
		{ID: "api.v1.session.renew", Method: "POST", Path: "/api/v1/session/renew", Availability: AvailabilityAvailable, OwnerPhase: "3", RequestSchema: apiBrowserSessionRequestSchemaID, DataSchema: apiBrowserSessionDataSchemaID, Stream: StreamFinite, Audiences: []EndpointAudience{AudienceBrowser}},
		{ID: "api.v1.session.logout", Method: "POST", Path: "/api/v1/session/logout", Availability: AvailabilityAvailable, OwnerPhase: "3", RequestSchema: apiBrowserSessionRequestSchemaID, DataSchema: apiBrowserSessionDataSchemaID, Stream: StreamFinite, Audiences: []EndpointAudience{AudienceBrowser}},
	}
}

func operatorCommand(path []string, summary, requestSchema, dataSchema string, flags []FlagDefinition, example []string) CommandDefinition {
	return CommandDefinition{Path: path, Summary: summary, Availability: AvailabilityAvailable, OwnerPhase: "2", Risk: RiskReadOnly,
		Flags: append(flags, commonFlags()...), RequestSchema: requestSchema, ResultSchema: runResultSchemaID, DataSchema: dataSchema,
		Examples: []ExampleDefinition{{Summary: summary, Arguments: example}}}
}

func platformStatusCommand() CommandDefinition {
	return operatorCommand([]string{"status"}, "Show the current platform summary.", "", apiSummaryDataSchemaID,
		[]FlagDefinition{{Name: "--config", Kind: FlagValue, ValueName: "path", Required: true, Summary: "Read the protected server profile at this explicit path."}},
		[]string{"status", "--config", "fixture/server-profile.json", "--output", "json"})
}

func databaseStatusCommand() CommandDefinition {
	return operatorCommand([]string{"database", "status"}, "Inspect control-database status.", "", databaseStatusDataSchemaID,
		[]FlagDefinition{{Name: "--config", Kind: FlagValue, ValueName: "path", Required: true, Summary: "Read the protected server profile at this explicit path."}},
		[]string{"database", "status", "--config", "fixture/server-profile.json", "--output", "json"})
}

func inventoryImportCommand() CommandDefinition {
	return operatorCommand([]string{"inventory", "import"}, "Validate and store one inventory candidate as an inert draft.", inventoryImportRequestSchemaID, inventoryImportDataSchemaID,
		[]FlagDefinition{
			{Name: "--config", Kind: FlagValue, ValueName: "path", Required: true, Summary: "Read the protected server profile at this explicit path."},
			{Name: "--file", Kind: FlagValue, ValueName: "path", Required: true, Summary: "Read one protected local candidate file."},
			{Name: "--format", Kind: FlagValue, ValueName: "format", Required: true, Summary: "Select the explicit candidate format.", Enum: []string{"typed-json", "labs-sheet1-csv"}},
			{Name: "--source-revision", Kind: FlagValue, ValueName: "revision", Required: true, Summary: "Record the source revision supplied by its owner."},
			{Name: "--captured-at", Kind: FlagValue, ValueName: "timestamp", Required: true, Summary: "Record an RFC 3339 UTC capture time."},
			{Name: "--idempotency-key", Kind: FlagValue, ValueName: "key", Required: true, Summary: "Supply one opaque retry key."},
			{Name: "--expected-state-revision", Kind: FlagValue, ValueName: "revision", Summary: "Require this current state revision."},
		}, []string{"inventory", "import", "--config", "fixture/server-profile.json", "--file", "fixture/inventory.json", "--format", "typed-json", "--source-revision", "source-1", "--captured-at", "2026-09-08T06:00:00Z", "--idempotency-key", "opaque-1", "--output", "json"})
}

func inventoryDiffCommand() CommandDefinition {
	return operatorCommand([]string{"inventory", "diff"}, "Compare one inert draft or local candidate with a compatible inert draft.", inventoryDiffRequestSchemaID, inventoryDiffDataSchemaID,
		[]FlagDefinition{
			{Name: "--config", Kind: FlagValue, ValueName: "path", Required: true, Summary: "Read the protected server profile at this explicit path."},
			{Name: "--draft-id", Kind: FlagValue, ValueName: "id", Summary: "Select an existing inert draft."},
			{Name: "--draft-revision", Kind: FlagValue, ValueName: "revision", Summary: "Select the exact inert draft revision."},
			{Name: "--file", Kind: FlagValue, ValueName: "path", Summary: "Read one protected local candidate file."},
			{Name: "--format", Kind: FlagValue, ValueName: "format", Summary: "Select the explicit candidate format.", Enum: []string{"typed-json", "labs-sheet1-csv"}},
			{Name: "--source-revision", Kind: FlagValue, ValueName: "revision", Summary: "Record the source revision supplied by its owner."},
			{Name: "--captured-at", Kind: FlagValue, ValueName: "timestamp", Summary: "Record an RFC 3339 UTC capture time."},
		}, []string{"inventory", "diff", "--config", "fixture/server-profile.json", "--draft-id", "draft-test", "--draft-revision", "1", "--output", "json"})
}

func inventoryExportCommand() CommandDefinition {
	return operatorCommand([]string{"inventory", "export"}, "Publish one verified signed inert-draft export.", inventoryExportRequestSchemaID, inventoryExportDataSchemaID,
		[]FlagDefinition{
			{Name: "--config", Kind: FlagValue, ValueName: "path", Required: true, Summary: "Read the protected server profile at this explicit path."},
			{Name: "--draft-id", Kind: FlagValue, ValueName: "id", Required: true, Summary: "Select an existing inert draft."},
			{Name: "--draft-revision", Kind: FlagValue, ValueName: "revision", Required: true, Summary: "Select the exact inert draft revision."},
		}, []string{"inventory", "export", "--config", "fixture/server-profile.json", "--draft-id", "draft-test", "--draft-revision", "1", "--output", "json"})
}

func serverRunCommand() CommandDefinition {
	return CommandDefinition{
		Path:         []string{"server", "run"},
		Summary:      "Run the persistent control service in the foreground.",
		Availability: AvailabilityAvailable,
		OwnerPhase:   "2",
		Risk:         RiskLocalService,
		Flags: append([]FlagDefinition{
			{Name: "--config", Kind: FlagValue, ValueName: "path", Required: true, Summary: "Read the protected server profile at this explicit path."},
		}, commonFlags()...),
		ResultSchema: runResultSchemaID,
		Examples:     []ExampleDefinition{{Summary: "Run the local control service in the foreground.", Arguments: []string{"server", "run", "--config", "fixture/server-profile.json"}}},
	}
}

func serverStatusCommand() CommandDefinition {
	return CommandDefinition{
		Path:         []string{"server", "status"},
		Summary:      "Query control-service health.",
		Availability: AvailabilityAvailable,
		OwnerPhase:   "2",
		Risk:         RiskReadOnly,
		Flags: append([]FlagDefinition{
			{Name: "--config", Kind: FlagValue, ValueName: "path", Required: true, Summary: "Read the protected server profile at this explicit path."},
		}, commonFlags()...),
		ResultSchema: runResultSchemaID,
		DataSchema:   serverStatusDataSchemaID,
		Examples:     []ExampleDefinition{{Summary: "Query local control-service health as versioned JSON.", Arguments: []string{"server", "status", "--config", "fixture/server-profile.json", "--output", "json"}}},
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
				Kind:      FlagValue,
				ValueName: "format",
				Summary:   "Select human or versioned JSON output.",
				Enum:      []string{"human", "json"},
			},
			{
				Name:      "--schema-version",
				Kind:      FlagValue,
				ValueName: "major",
				Summary:   "Select the machine-contract schema major.",
				Enum:      []string{"1"},
			},
		},
		ResultSchema: runResultSchemaID,
		Examples:     examples,
	}
}

func releaseInspectCommand() CommandDefinition {
	return CommandDefinition{
		Path:         []string{"release", "inspect"},
		Summary:      "Inspect a local release manifest and compatibility without claiming cryptographic verification.",
		Availability: AvailabilityAvailable,
		OwnerPhase:   "1",
		Risk:         RiskReadOnly,
		Flags: append([]FlagDefinition{
			{Name: "--manifest", Kind: FlagValue, ValueName: "path", Required: true, Summary: "Read the local release manifest at this path."},
		}, commonFlags()...),
		ResultSchema: runResultSchemaID,
		DataSchema:   releaseInspectDataSchemaID,
		Examples: []ExampleDefinition{
			{Summary: "Inspect a local manifest as versioned JSON.", Arguments: []string{"release", "inspect", "--manifest", "release/manifest.json", "--output", "json"}},
		},
	}
}

func releaseVerifyCommand() CommandDefinition {
	return CommandDefinition{
		Path:         []string{"release", "verify"},
		Summary:      "Verify a signed local manifest and explicitly selected assets against a supplied offline policy.",
		Availability: AvailabilityAvailable,
		OwnerPhase:   "1",
		Risk:         RiskReadOnly,
		Flags: append([]FlagDefinition{
			{Name: "--manifest", Kind: FlagValue, ValueName: "path", Required: true, Summary: "Read the local release manifest at this path."},
			{Name: "--policy", Kind: FlagValue, ValueName: "path", Required: true, Summary: "Read the supplied local trust policy at this path."},
			{Name: "--asset", Kind: FlagValue, ValueName: "id", Repeatable: true, Summary: "Verify one named asset; repeat for additional assets."},
			{Name: "--all", Kind: FlagSwitch, Summary: "Explicitly verify every asset in the manifest."},
		}, commonFlags()...),
		ResultSchema: runResultSchemaID,
		DataSchema:   releaseVerifyDataSchemaID,
		Examples: []ExampleDefinition{
			{Summary: "Verify one local asset against a supplied policy.", Arguments: []string{"release", "verify", "--manifest", "release/manifest.json", "--policy", "release/policy.json", "--asset", "linux-amd64", "--output", "json"}},
			{Summary: "Explicitly verify every local asset.", Arguments: []string{"release", "verify", "--manifest", "release/manifest.json", "--policy", "release/policy.json", "--all"}},
		},
	}
}

func commonFlags() []FlagDefinition {
	return []FlagDefinition{
		{Name: "--output", Kind: FlagValue, ValueName: "format", Summary: "Select human or versioned JSON output.", Enum: []string{"human", "json"}},
		{Name: "--schema-version", Kind: FlagValue, ValueName: "major", Summary: "Select the machine-contract schema major.", Enum: []string{"1"}},
	}
}

func currentSchemas() []SchemaDefinition {
	schemas := []SchemaDefinition{
		{
			ID:           databaseStatusDataSchemaID,
			Version:      "1.0.0",
			ArtifactPath: "schemas/v1/database-status-data.schema.json",
			Fields: []FieldDefinition{
				{JSONName: "mode", GoName: "Mode", Kind: ValueString, Required: true, Enum: []string{"ready", "safe-mode"}},
				{JSONName: "schemaVersion", GoName: "SchemaVersion", Kind: ValueInteger, Required: true, Minimum: int64Pointer(0)},
				{JSONName: "sqliteVersion", GoName: "SQLiteVersion", Kind: ValueString, Required: true},
				{JSONName: "mutationEnabled", GoName: "MutationEnabled", Kind: ValueBoolean, Required: true},
				{JSONName: "recoveryPending", GoName: "RecoveryPending", Kind: ValueBoolean, Required: true},
				{JSONName: "integrityStatus", GoName: "IntegrityStatus", Kind: ValueString, Required: true, Enum: []string{"unknown", "verified", "failed"}},
				{JSONName: "lastIntegrityCheckAt", GoName: "LastIntegrityCheckAt", Kind: ValueString, Required: true, Nullable: true},
				{JSONName: "safeModeReason", GoName: "SafeModeReason", Kind: ValueString, Required: true},
			},
		},
		{
			ID:      localPrincipalBindingSchemaID,
			Version: "1.0.0",
			Fields: []FieldDefinition{
				{JSONName: "uid", GoName: "UID", Kind: ValueInteger, Required: true, Minimum: int64Pointer(0), Maximum: int64Pointer(4294967295)},
				{JSONName: "principalId", GoName: "PrincipalID", Kind: ValueString, Required: true, Pattern: `^[a-z][a-z0-9._:-]{0,127}$`},
			},
		},
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
			ID:           runResultSchemaID,
			Version:      "1.0.0",
			ArtifactPath: "schemas/v1/run-result.schema.json",
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
		{
			ID:      releaseAssetSchemaID,
			Version: "1.0.0",
			Fields: []FieldDefinition{
				{JSONName: "id", GoName: "ID", Kind: ValueString, Required: true, Pattern: `^[a-z0-9][a-z0-9._-]{0,63}$`},
				{JSONName: "kind", GoName: "Kind", Kind: ValueString, Required: true, Enum: []string{"archive", "executable", "package"}},
				{JSONName: "os", GoName: "OS", Kind: ValueString, Required: true, Enum: []string{"darwin", "linux", "windows"}},
				{JSONName: "architecture", GoName: "Architecture", Kind: ValueString, Required: true, Enum: []string{"amd64", "arm64"}},
				{JSONName: "path", GoName: "Path", Kind: ValueString, Required: true, Pattern: `^[^/\\].*`},
				{JSONName: "size", GoName: "Size", Kind: ValueInteger, Required: true, Minimum: int64Pointer(1), Maximum: int64Pointer(8 * 1024 * 1024 * 1024)},
				{JSONName: "digest", GoName: "Digest", Kind: ValueString, Required: true, Pattern: `^sha256:[0-9a-f]{64}$`},
				{JSONName: "bundlePath", GoName: "BundlePath", Kind: ValueString, Required: true, Pattern: `^[^/\\].*`},
				{JSONName: "sbomPath", GoName: "SBOMPath", Kind: ValueString, Nullable: true, Pattern: `^[^/\\].*`},
				{JSONName: "provenancePath", GoName: "ProvenancePath", Kind: ValueString, Nullable: true, Pattern: `^[^/\\].*`},
			},
		},
		{
			ID:           releaseManifestSchemaID,
			Version:      "1.0.0",
			ArtifactPath: "schemas/v1/release-manifest.schema.json",
			Fields: []FieldDefinition{
				{JSONName: "schema", GoName: "Schema", Kind: ValueString, Required: true, Enum: []string{releaseManifestSchemaID}},
				{JSONName: "schemaVersion", GoName: "SchemaVersion", Kind: ValueString, Required: true, Enum: []string{"1.0.0"}},
				{JSONName: "releaseId", GoName: "ReleaseID", Kind: ValueString, Required: true, Pattern: `^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`},
				{JSONName: "buildId", GoName: "BuildID", Kind: ValueString, Required: true, Pattern: `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`},
				{JSONName: "sourceRevision", GoName: "SourceRevision", Kind: ValueString, Required: true, Pattern: `^[0-9a-f]{40,64}$`},
				{JSONName: "minimumSchemaMajor", GoName: "MinimumSchemaMajor", Kind: ValueInteger, Required: true, Minimum: int64Pointer(1)},
				{JSONName: "maximumSchemaMajor", GoName: "MaximumSchemaMajor", Kind: ValueInteger, Required: true, Minimum: int64Pointer(1)},
				{JSONName: "bundlePath", GoName: "BundlePath", Kind: ValueString, Required: true, Pattern: `^[^/\\].*`},
				{JSONName: "assets", GoName: "Assets", Kind: ValueArray, Required: true, ItemRef: releaseAssetSchemaID, MinItems: intPointer(1), MaxItems: intPointer(64), UniqueItems: true},
			},
		},
		{
			ID:           releaseTrustPolicySchemaID,
			Version:      "1.0.0",
			ArtifactPath: "schemas/v1/release-trust-policy.schema.json",
			Fields: []FieldDefinition{
				{JSONName: "schema", GoName: "Schema", Kind: ValueString, Required: true, Enum: []string{releaseTrustPolicySchemaID}},
				{JSONName: "schemaVersion", GoName: "SchemaVersion", Kind: ValueString, Required: true, Enum: []string{"1.0.0"}},
				{JSONName: "certificateIdentity", GoName: "CertificateIdentity", Kind: ValueString, Required: true},
				{JSONName: "oidcIssuer", GoName: "OIDCIssuer", Kind: ValueString, Required: true},
				{JSONName: "trustedRoot", GoName: "TrustedRoot", Kind: ValueObject, Required: true, AdditionalProperties: true},
			},
		},
		{
			ID:           releaseInspectDataSchemaID,
			Version:      "1.0.0",
			ArtifactPath: "schemas/v1/release-inspect-data.schema.json",
			Fields: []FieldDefinition{
				{JSONName: "releaseId", GoName: "ReleaseID", Kind: ValueString, Required: true},
				{JSONName: "buildId", GoName: "BuildID", Kind: ValueString, Required: true},
				{JSONName: "sourceRevision", GoName: "SourceRevision", Kind: ValueString, Required: true},
				{JSONName: "minimumSchemaMajor", GoName: "MinimumSchemaMajor", Kind: ValueInteger, Required: true},
				{JSONName: "maximumSchemaMajor", GoName: "MaximumSchemaMajor", Kind: ValueInteger, Required: true},
				{JSONName: "platformOs", GoName: "PlatformOS", Kind: ValueString, Required: true},
				{JSONName: "platformArchitecture", GoName: "PlatformArchitecture", Kind: ValueString, Required: true},
				{JSONName: "platformSchemaMajor", GoName: "PlatformSchemaMajor", Kind: ValueInteger, Required: true},
				{JSONName: "compatibleAssetIds", GoName: "CompatibleAssetIDs", Kind: ValueArray, Required: true, ItemKind: ValueString, UniqueItems: true},
				{JSONName: "assets", GoName: "Assets", Kind: ValueArray, Required: true, ItemRef: releaseAssetSchemaID},
				{JSONName: "verificationStatus", GoName: "VerificationStatus", Kind: ValueString, Required: true, Enum: []string{"not-verified"}},
			},
		},
		{
			ID:      releaseAssetVerificationSchemaID,
			Version: "1.0.0",
			Fields: []FieldDefinition{
				{JSONName: "assetId", GoName: "AssetID", Kind: ValueString, Required: true},
				{JSONName: "os", GoName: "OS", Kind: ValueString, Required: true},
				{JSONName: "architecture", GoName: "Architecture", Kind: ValueString, Required: true},
				{JSONName: "digest", GoName: "Digest", Kind: ValueString, Required: true},
				{JSONName: "size", GoName: "Size", Kind: ValueInteger, Required: true},
				{JSONName: "status", GoName: "Status", Kind: ValueString, Required: true, Enum: []string{"verified"}},
			},
		},
		{
			ID:           releaseVerifyDataSchemaID,
			Version:      "1.0.0",
			ArtifactPath: "schemas/v1/release-verify-data.schema.json",
			Fields: []FieldDefinition{
				{JSONName: "releaseId", GoName: "ReleaseID", Kind: ValueString, Required: true},
				{JSONName: "buildId", GoName: "BuildID", Kind: ValueString, Required: true},
				{JSONName: "sourceRevision", GoName: "SourceRevision", Kind: ValueString, Required: true},
				{JSONName: "manifestStatus", GoName: "ManifestStatus", Kind: ValueString, Required: true, Enum: []string{"verified"}},
				{JSONName: "verificationStatus", GoName: "VerificationStatus", Kind: ValueString, Required: true, Enum: []string{"verified-against-supplied-policy"}},
				{JSONName: "policySha256", GoName: "PolicySHA256", Kind: ValueString, Required: true, Pattern: `^sha256:[0-9a-f]{64}$`},
				{JSONName: "assets", GoName: "Assets", Kind: ValueArray, Required: true, ItemRef: releaseAssetVerificationSchemaID, MinItems: intPointer(1), MaxItems: intPointer(64)},
			},
		},
		{
			ID:      remoteReadProfileSchemaID,
			Version: "1.0.0",
			Fields: []FieldDefinition{
				{JSONName: "enabled", GoName: "Enabled", Kind: ValueBoolean, Required: true},
				{JSONName: "bindAddress", GoName: "BindAddress", Kind: ValueString, Required: true, Nullable: true, MinLength: intPointer(1), MaxLength: intPointer(512)},
				{JSONName: "publicOrigin", GoName: "PublicOrigin", Kind: ValueString, Required: true, Nullable: true, MinLength: intPointer(1), MaxLength: intPointer(2048)},
				{JSONName: "tlsCertificatePath", GoName: "TLSCertificatePath", Kind: ValueString, Required: true, Nullable: true, MinLength: intPointer(2), MaxLength: intPointer(4096)},
				{JSONName: "tlsPrivateKeyPath", GoName: "TLSPrivateKeyPath", Kind: ValueString, Required: true, Nullable: true, MinLength: intPointer(2), MaxLength: intPointer(4096)},
				{JSONName: "identityAdapter", GoName: "IdentityAdapter", Kind: ValueString, Required: true, Nullable: true, Pattern: `^[a-z][a-z0-9-]{0,63}$`},
				{JSONName: "identityConfigPath", GoName: "IdentityConfigPath", Kind: ValueString, Required: true, Nullable: true, MinLength: intPointer(2), MaxLength: intPointer(4096)},
			},
		},
		{
			ID:           cloudflareAccessProfileSchemaID,
			Version:      "1.0.0",
			ArtifactPath: "schemas/v1/cloudflare-access-profile.schema.json",
			Fields: []FieldDefinition{
				{JSONName: "schema", GoName: "Schema", Kind: ValueString, Required: true, Enum: []string{cloudflareAccessProfileSchemaID}},
				{JSONName: "schemaVersion", GoName: "SchemaVersion", Kind: ValueString, Required: true, Enum: []string{"1.0.0"}},
				{JSONName: "issuer", GoName: "Issuer", Kind: ValueString, Required: true, MinLength: intPointer(1), MaxLength: intPointer(2048)},
				{JSONName: "audience", GoName: "Audience", Kind: ValueString, Required: true, MinLength: intPointer(1), MaxLength: intPointer(4096)},
				{JSONName: "certificatesUrl", GoName: "CertificatesURL", Kind: ValueString, Required: true, MinLength: intPointer(1), MaxLength: intPointer(2048)},
				{JSONName: "clockSkewSeconds", GoName: "ClockSkewSeconds", Kind: ValueInteger, Required: true, Minimum: int64Pointer(0), Maximum: int64Pointer(300)},
				{JSONName: "maxTokenBytes", GoName: "MaxTokenBytes", Kind: ValueInteger, Required: true, Minimum: int64Pointer(1024), Maximum: int64Pointer(65536)},
				{JSONName: "knownKeyOutageSeconds", GoName: "KnownKeyOutageSeconds", Kind: ValueInteger, Required: true, Minimum: int64Pointer(1), Maximum: int64Pointer(86400)},
			},
		},
		{
			ID:           serverProfileSchemaID,
			Version:      "1.1.0",
			ArtifactPath: "schemas/v1/server-profile.schema.json",
			Fields: []FieldDefinition{
				{JSONName: "schema", GoName: "Schema", Kind: ValueString, Required: true, Enum: []string{serverProfileSchemaID}},
				{JSONName: "schemaVersion", GoName: "SchemaVersion", Kind: ValueString, Required: true, Enum: []string{"1.1.0"}},
				{JSONName: "socketPath", GoName: "SocketPath", Kind: ValueString, Required: true, Pattern: `^/[^\x00]*$`, MinLength: intPointer(2), MaxLength: intPointer(107)},
				{JSONName: "socketOwnerUid", GoName: "SocketOwnerUID", Kind: ValueInteger, Required: true, Minimum: int64Pointer(0), Maximum: int64Pointer(4294967295)},
				{JSONName: "socketGroupGid", GoName: "SocketGroupGID", Kind: ValueInteger, Required: true, Nullable: true, Minimum: int64Pointer(0), Maximum: int64Pointer(4294967295)},
				{JSONName: "socketMode", GoName: "SocketMode", Kind: ValueString, Required: true, Enum: []string{"0600", "0660"}},
				{JSONName: "shutdownGraceSeconds", GoName: "ShutdownGraceSeconds", Kind: ValueInteger, Required: true, Minimum: int64Pointer(5), Maximum: int64Pointer(5)},
				{JSONName: "inventoryExportRoot", GoName: "InventoryExportRoot", Kind: ValueString, Required: true, Pattern: `^/[^\x00]*$`, MinLength: intPointer(2), MaxLength: intPointer(4096)},
				{JSONName: "principalBindings", GoName: "PrincipalBindings", Kind: ValueArray, Required: true, ItemRef: localPrincipalBindingSchemaID, MinItems: intPointer(1), MaxItems: intPointer(256), UniqueItems: true},
				{JSONName: "remoteRead", GoName: "RemoteRead", Kind: ValueObject, Required: true, Ref: remoteReadProfileSchemaID},
				{JSONName: "acknowledgementAdapterConfigPath", GoName: "AcknowledgementAdapterConfigPath", Kind: ValueString, Required: false, MinLength: intPointer(2), MaxLength: intPointer(4096), Pattern: `^/[^\x00]*$`},
			},
		},
		{
			ID:           serverStatusDataSchemaID,
			Version:      "1.1.0",
			ArtifactPath: "schemas/v1/server-status-data.schema.json",
			Fields: []FieldDefinition{
				{JSONName: "state", GoName: "State", Kind: ValueString, Required: true, Enum: []string{"starting", "ready", "safe-mode", "stopping", "unavailable"}},
				{JSONName: "readAvailable", GoName: "ReadAvailable", Kind: ValueBoolean, Required: true},
				{JSONName: "mutationAvailable", GoName: "MutationAvailable", Kind: ValueBoolean, Required: true},
				{JSONName: "recoveryEpoch", GoName: "RecoveryEpoch", Kind: ValueInteger, Required: true},
				{JSONName: "stateRevision", GoName: "StateRevision", Kind: ValueInteger, Required: true},
				{JSONName: "remoteReadState", GoName: "RemoteReadState", Kind: ValueString, Required: true, Enum: []string{"disabled", "starting", "ready", "unavailable"}},
				{JSONName: "remoteReadReason", GoName: "RemoteReadReason", Kind: ValueString, Required: true, Enum: []string{"none", "preflight-unavailable", "authentication-unavailable", "listener-unavailable", "serve-failed"}},
			},
		},
	}
	schemas = append(schemas, inventorySchemas()...)
	schemas = append(schemas, stateExportSchemas()...)
	schemas = append(schemas, auditSchemas()...)
	schemas = append(schemas, readAPISchemas()...)
	schemas = append(schemas, inventoryOperationSchemas()...)
	return append(schemas, phase4Schemas()...)
}

func inventoryOperationSchemas() []SchemaDefinition {
	token := `^[A-Za-z0-9][A-Za-z0-9._+:-]{0,127}$`
	digest := `^sha256:[0-9a-f]{64}$`
	int0 := func(name, goName string) FieldDefinition {
		return FieldDefinition{JSONName: name, GoName: goName, Kind: ValueInteger, Required: true, Minimum: int64Pointer(0)}
	}
	return []SchemaDefinition{
		{ID: inventoryDraftRefSchemaID, Version: "1.0.0", Fields: []FieldDefinition{
			{JSONName: "draftId", GoName: "DraftID", Kind: ValueString, Required: true, Pattern: token, MaxLength: intPointer(128)},
			{JSONName: "draftRevision", GoName: "DraftRevision", Kind: ValueInteger, Required: true, Minimum: int64Pointer(1)},
		}},
		{ID: inventoryImportRequestSchemaID, Version: "1.0.0", ArtifactPath: "schemas/v1/inventory-import-request.schema.json", Fields: []FieldDefinition{
			{JSONName: "format", GoName: "Format", Kind: ValueString, Required: true, Enum: []string{"typed-json", "labs-sheet1-csv"}},
			{JSONName: "sourceRevision", GoName: "SourceRevision", Kind: ValueString, Required: true, MinLength: intPointer(1), MaxLength: intPointer(128)},
			{JSONName: "capturedAt", GoName: "CapturedAt", Kind: ValueString, Required: true, MinLength: intPointer(20), MaxLength: intPointer(64)},
			{JSONName: "idempotencyKey", GoName: "IdempotencyKey", Kind: ValueString, Required: true, MinLength: intPointer(1), MaxLength: intPointer(256)},
			{JSONName: "expectedStateRevision", GoName: "ExpectedStateRevision", Kind: ValueInteger, Required: true, Nullable: true, Minimum: int64Pointer(0)},
			{JSONName: "content", GoName: "Content", Kind: ValueString, Required: true, MinLength: intPointer(1), MaxLength: intPointer(4 << 20)},
		}},
		{ID: inventoryDiffRequestSchemaID, Version: "1.0.0", ArtifactPath: "schemas/v1/inventory-diff-request.schema.json", Fields: []FieldDefinition{
			{JSONName: "candidateKind", GoName: "CandidateKind", Kind: ValueString, Required: true, Enum: []string{"draft", "file"}},
			{JSONName: "draft", GoName: "Draft", Kind: ValueObject, Required: true, Nullable: true, Ref: inventoryDraftRefSchemaID},
			{JSONName: "format", GoName: "Format", Kind: ValueString, Required: true, Nullable: true, Enum: []string{"typed-json", "labs-sheet1-csv"}},
			{JSONName: "sourceRevision", GoName: "SourceRevision", Kind: ValueString, Required: true, Nullable: true, MaxLength: intPointer(128)},
			{JSONName: "capturedAt", GoName: "CapturedAt", Kind: ValueString, Required: true, Nullable: true, MaxLength: intPointer(64)},
			{JSONName: "content", GoName: "Content", Kind: ValueString, Required: true, Nullable: true, MaxLength: intPointer(4 << 20)},
		}},
		{ID: inventoryFieldChangeSchemaID, Version: "1.0.0", Fields: []FieldDefinition{
			{JSONName: "path", GoName: "Path", Kind: ValueString, Required: true, MinLength: intPointer(1), MaxLength: intPointer(256)},
			{JSONName: "before", GoName: "Before", Kind: ValueString, Required: true, Nullable: true, MaxLength: intPointer(2048)},
			{JSONName: "after", GoName: "After", Kind: ValueString, Required: true, Nullable: true, MaxLength: intPointer(2048)},
		}},
		{ID: inventoryDiffRecordSchemaID, Version: "1.0.0", Fields: []FieldDefinition{
			{JSONName: "change", GoName: "Change", Kind: ValueString, Required: true, Enum: []string{"added", "removed", "changed", "unchanged"}},
			{JSONName: "recordKind", GoName: "RecordKind", Kind: ValueString, Required: true, Enum: []string{"asset", "node", "alias", "address", "observation", "provenance"}},
			{JSONName: "localId", GoName: "LocalID", Kind: ValueString, Required: true, Pattern: token, MaxLength: intPointer(128)},
			{JSONName: "fields", GoName: "Fields", Kind: ValueArray, Required: true, ItemRef: inventoryFieldChangeSchemaID, MaxItems: intPointer(128)},
		}},
		{ID: inventoryDiffCountsSchemaID, Version: "1.0.0", Fields: []FieldDefinition{int0("added", "Added"), int0("removed", "Removed"), int0("changed", "Changed"), int0("unchanged", "Unchanged")}},
		{ID: inventoryDiffDataSchemaID, Version: "1.0.0", ArtifactPath: "schemas/v1/inventory-diff-data.schema.json", Fields: []FieldDefinition{
			{JSONName: "candidateKind", GoName: "CandidateKind", Kind: ValueString, Required: true, Enum: []string{"draft", "file"}},
			{JSONName: "candidateDraft", GoName: "CandidateDraft", Kind: ValueObject, Required: true, Nullable: true, Ref: inventoryDraftRefSchemaID},
			{JSONName: "candidateDigest", GoName: "CandidateDigest", Kind: ValueString, Required: true, Pattern: digest},
			{JSONName: "baselineKind", GoName: "BaselineKind", Kind: ValueString, Required: true, Enum: []string{"draft"}},
			{JSONName: "baselineDraft", GoName: "BaselineDraft", Kind: ValueObject, Required: true, Ref: inventoryDraftRefSchemaID},
			int0("stateRevision", "StateRevision"), int0("recoveryEpoch", "RecoveryEpoch"),
			{JSONName: "counts", GoName: "Counts", Kind: ValueObject, Required: true, Ref: inventoryDiffCountsSchemaID},
			{JSONName: "records", GoName: "Records", Kind: ValueArray, Required: true, ItemRef: inventoryDiffRecordSchemaID, MaxItems: intPointer(32768)},
			{JSONName: "findings", GoName: "Findings", Kind: ValueArray, Required: true, ItemRef: inventoryFindingSchemaID, MaxItems: intPointer(16384)},
		}},
		{ID: inventoryExportRequestSchemaID, Version: "1.0.0", ArtifactPath: "schemas/v1/inventory-export-request.schema.json", Fields: []FieldDefinition{
			{JSONName: "draft", GoName: "Draft", Kind: ValueObject, Required: true, Ref: inventoryDraftRefSchemaID},
		}},
		{ID: inventoryExportDataSchemaID, Version: "1.0.0", ArtifactPath: "schemas/v1/inventory-export-data.schema.json", Fields: []FieldDefinition{
			{JSONName: "exportId", GoName: "ExportID", Kind: ValueString, Required: true, Pattern: digest},
			{JSONName: "subjectKind", GoName: "SubjectKind", Kind: ValueString, Required: true, Enum: []string{"draft"}},
			{JSONName: "draft", GoName: "Draft", Kind: ValueObject, Required: true, Ref: inventoryDraftRefSchemaID},
			int0("stateRevision", "StateRevision"), int0("recoveryEpoch", "RecoveryEpoch"),
			{JSONName: "contentDigest", GoName: "ContentDigest", Kind: ValueString, Required: true, Pattern: digest},
			{JSONName: "algorithm", GoName: "Algorithm", Kind: ValueString, Required: true, Enum: []string{"ed25519"}},
			{JSONName: "keyId", GoName: "KeyID", Kind: ValueString, Required: true, Pattern: token, MaxLength: intPointer(128)},
			{JSONName: "keyFingerprint", GoName: "KeyFingerprint", Kind: ValueString, Required: true, Pattern: digest},
			{JSONName: "verificationStatus", GoName: "VerificationStatus", Kind: ValueString, Required: true, Enum: []string{"verified"}},
			{JSONName: "publicationStatus", GoName: "PublicationStatus", Kind: ValueString, Required: true, Enum: []string{"published"}},
			{JSONName: "signedBytesBase64", GoName: "SignedBytesBase64", Kind: ValueString, Required: true, Pattern: `^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$`, MaxLength: intPointer(24 << 20)},
		}},
	}
}

func readAPISchemas() []SchemaDefinition {
	intMin0 := func(name, goName string) FieldDefinition {
		return FieldDefinition{JSONName: name, GoName: goName, Kind: ValueInteger, Required: true, Minimum: int64Pointer(0)}
	}
	pageFields := func(itemRef string) []FieldDefinition {
		return []FieldDefinition{
			{JSONName: "items", GoName: "Items", Kind: ValueArray, Required: true, ItemRef: itemRef, MaxItems: intPointer(200)},
			{JSONName: "nextCursor", GoName: "NextCursor", Kind: ValueString, Required: true, Nullable: true, MaxLength: intPointer(2048)},
			intMin0("stateRevision", "StateRevision"), intMin0("recoveryEpoch", "RecoveryEpoch"),
		}
	}
	token := func(name, goName string) FieldDefinition {
		return FieldDefinition{JSONName: name, GoName: goName, Kind: ValueString, Required: true, MaxLength: intPointer(128)}
	}
	return []SchemaDefinition{
		{ID: apiBrowserSessionRequestSchemaID, Version: "1.0.0", ArtifactPath: "schemas/v1/api-browser-session-request.schema.json", Fields: []FieldDefinition{
			{JSONName: "requestVersion", GoName: "RequestVersion", Kind: ValueString, Required: true, Enum: []string{"1.0.0"}},
		}},
		{ID: apiBrowserSessionDataSchemaID, Version: "1.0.0", ArtifactPath: "schemas/v1/api-browser-session-data.schema.json", Fields: []FieldDefinition{
			{JSONName: "principalId", GoName: "PrincipalID", Kind: ValueString, Required: true, Pattern: `^[a-z][a-z0-9._:-]{0,127}$`},
			{JSONName: "idleExpiresAt", GoName: "IdleExpiresAt", Kind: ValueString, Required: true, MaxLength: intPointer(64)},
			{JSONName: "absoluteExpiresAt", GoName: "AbsoluteExpiresAt", Kind: ValueString, Required: true, MaxLength: intPointer(64)},
			{JSONName: "logoutScope", GoName: "LogoutScope", Kind: ValueString, Required: true, Enum: []string{"vsk-labs-session-only"}},
		}},
		{ID: apiPageQuerySchemaID, Version: "1.0.0", Fields: []FieldDefinition{
			{JSONName: "limit", GoName: "Limit", Kind: ValueInteger, Required: false, Minimum: int64Pointer(1), Maximum: int64Pointer(200)},
			{JSONName: "sort", GoName: "Sort", Kind: ValueString, Required: false, MaxLength: intPointer(64)},
			{JSONName: "cursor", GoName: "Cursor", Kind: ValueString, Required: false, MaxLength: intPointer(2048)},
		}},
		{ID: apiPageDataSchemaID, Version: "1.0.0", ArtifactPath: "schemas/v1/api-page-data.schema.json", Fields: []FieldDefinition{
			{JSONName: "nextCursor", GoName: "NextCursor", Kind: ValueString, Required: true, Nullable: true, MaxLength: intPointer(2048)}, intMin0("stateRevision", "StateRevision"), intMin0("recoveryEpoch", "RecoveryEpoch"),
		}},
		{ID: apiSourceListQuerySchemaID, Version: "1.0.0", ArtifactPath: "schemas/v1/api-source-list-query.schema.json", Fields: []FieldDefinition{
			{JSONName: "limit", GoName: "Limit", Kind: ValueInteger, Required: false, Minimum: int64Pointer(1), Maximum: int64Pointer(200)},
			{JSONName: "sort", GoName: "Sort", Kind: ValueString, Required: false, Enum: []string{"id-asc", "id-desc"}},
			{JSONName: "cursor", GoName: "Cursor", Kind: ValueString, Required: false, MaxLength: intPointer(2048)},
			{JSONName: "source", GoName: "Source", Kind: ValueString, Required: false, Enum: []string{"database", "nodes", "gates", "people", "services", "backups", "providers"}},
			{JSONName: "state", GoName: "State", Kind: ValueString, Required: false, Enum: []string{"healthy", "stale", "unknown", "unavailable", "failed"}},
		}},
		{ID: apiSourceCountsDataSchemaID, Version: "1.0.0", ArtifactPath: "schemas/v1/api-source-counts-data.schema.json", Fields: []FieldDefinition{
			intMin0("total", "Total"), intMin0("healthy", "Healthy"), intMin0("stale", "Stale"), intMin0("unknown", "Unknown"), intMin0("unavailable", "Unavailable"), intMin0("failed", "Failed"),
		}},
		{ID: apiSourceDataSchemaID, Version: "1.0.0", ArtifactPath: "schemas/v1/api-source-data.schema.json", Fields: []FieldDefinition{
			{JSONName: "id", GoName: "ID", Kind: ValueString, Required: true, Enum: []string{"database", "nodes", "gates", "people", "services", "backups", "providers"}},
			{JSONName: "capability", GoName: "Capability", Kind: ValueString, Required: true, Enum: []string{"database.status.read", "inventory.node.read", "gate.read", "identity.person.read", "service.read", "backup.status.read", "adapter.status.read"}},
			{JSONName: "state", GoName: "State", Kind: ValueString, Required: true, Enum: []string{"healthy", "stale", "unknown", "unavailable", "failed"}},
			{JSONName: "collectedAt", GoName: "CollectedAt", Kind: ValueString, Required: true, Nullable: true, MaxLength: intPointer(64)},
			{JSONName: "lastSuccessAt", GoName: "LastSuccessAt", Kind: ValueString, Required: true, Nullable: true, MaxLength: intPointer(64)},
			{JSONName: "lastErrorAt", GoName: "LastErrorAt", Kind: ValueString, Required: true, Nullable: true, MaxLength: intPointer(64)},
			{JSONName: "reason", GoName: "Reason", Kind: ValueString, Required: true, Enum: []string{"source observation is current", "source observation is stale", "source has no observation timestamp", "source capability is unavailable", "source reported a collection failure"}},
		}},
		{ID: apiSourceListDataSchemaID, Version: "1.0.0", ArtifactPath: "schemas/v1/api-source-list-data.schema.json", Fields: pageFields(apiSourceDataSchemaID)},
		{ID: apiSummaryDataSchemaID, Version: "1.1.0", ArtifactPath: "schemas/v1/api-summary-data.schema.json", Fields: []FieldDefinition{
			{JSONName: "databaseMode", GoName: "DatabaseMode", Kind: ValueString, Required: true, Enum: []string{"ready", "safe-mode"}},
			{JSONName: "readAvailable", GoName: "ReadAvailable", Kind: ValueBoolean, Required: true},
			{JSONName: "mutationAvailable", GoName: "MutationAvailable", Kind: ValueBoolean, Required: true},
			intMin0("draftCount", "DraftCount"), intMin0("validDraftCount", "ValidDraftCount"), intMin0("blockedDraftCount", "BlockedDraftCount"), intMin0("lastEventId", "LastEventID"), intMin0("recoveryEpoch", "RecoveryEpoch"), intMin0("stateRevision", "StateRevision"),
			{JSONName: "sourceCounts", GoName: "SourceCounts", Kind: ValueObject, Required: true, Ref: apiSourceCountsDataSchemaID},
			{JSONName: "worstSourceState", GoName: "WorstSourceState", Kind: ValueString, Required: true, Enum: []string{"healthy", "stale", "unknown", "unavailable", "failed"}},
		}},
		{ID: apiInventoryDraftDataSchemaID, Version: "1.0.0", ArtifactPath: "schemas/v1/api-inventory-draft-data.schema.json", Fields: []FieldDefinition{
			{JSONName: "authority", GoName: "Authority", Kind: ValueString, Required: true, Enum: []string{"draft"}}, token("draftId", "DraftID"),
			{JSONName: "revision", GoName: "Revision", Kind: ValueInteger, Required: true, Minimum: int64Pointer(1)},
			{JSONName: "validationStatus", GoName: "ValidationStatus", Kind: ValueString, Required: true, Enum: []string{"valid", "blocked"}},
			token("contentDigest", "ContentDigest"), {JSONName: "createdAt", GoName: "CreatedAt", Kind: ValueString, Required: true, MaxLength: intPointer(64)},
			{JSONName: "counts", GoName: "Counts", Kind: ValueObject, Required: true, Ref: inventoryDraftCountsSchemaID},
		}},
		{ID: apiInventoryDraftListDataSchemaID, Version: "1.0.0", ArtifactPath: "schemas/v1/api-inventory-draft-list-data.schema.json", Fields: pageFields(apiInventoryDraftDataSchemaID)},
		{ID: apiInventoryAssetDataSchemaID, Version: "1.0.0", ArtifactPath: "schemas/v1/api-inventory-asset-data.schema.json", Fields: []FieldDefinition{
			{JSONName: "authority", GoName: "Authority", Kind: ValueString, Required: true, Enum: []string{"draft"}}, {JSONName: "validationStatus", GoName: "ValidationStatus", Kind: ValueString, Required: true, Enum: []string{"valid", "blocked"}}, token("id", "ID"), token("kind", "Kind"), token("lifecycle", "Lifecycle"),
		}},
		{ID: apiInventoryAssetListDataSchemaID, Version: "1.0.0", ArtifactPath: "schemas/v1/api-inventory-asset-list-data.schema.json", Fields: pageFields(apiInventoryAssetDataSchemaID)},
		{ID: apiInventoryNodeDataSchemaID, Version: "1.0.0", ArtifactPath: "schemas/v1/api-inventory-node-data.schema.json", Fields: []FieldDefinition{{JSONName: "authority", GoName: "Authority", Kind: ValueString, Required: true, Enum: []string{"draft"}}, {JSONName: "validationStatus", GoName: "ValidationStatus", Kind: ValueString, Required: true, Enum: []string{"valid", "blocked"}}, token("id", "ID"), token("assetId", "AssetID"), {JSONName: "parentId", GoName: "ParentID", Kind: ValueString, Required: true, MaxLength: intPointer(128)}}},
		{ID: apiInventoryNodeListDataSchemaID, Version: "1.0.0", ArtifactPath: "schemas/v1/api-inventory-node-list-data.schema.json", Fields: pageFields(apiInventoryNodeDataSchemaID)},
		{ID: apiInventoryAliasDataSchemaID, Version: "1.0.0", ArtifactPath: "schemas/v1/api-inventory-alias-data.schema.json", Fields: []FieldDefinition{{JSONName: "authority", GoName: "Authority", Kind: ValueString, Required: true, Enum: []string{"draft"}}, {JSONName: "validationStatus", GoName: "ValidationStatus", Kind: ValueString, Required: true, Enum: []string{"valid", "blocked"}}, token("id", "ID"), token("targetId", "TargetID"), {JSONName: "value", GoName: "Value", Kind: ValueString, Required: true, MaxLength: intPointer(1024)}}},
		{ID: apiInventoryAliasListDataSchemaID, Version: "1.0.0", ArtifactPath: "schemas/v1/api-inventory-alias-list-data.schema.json", Fields: pageFields(apiInventoryAliasDataSchemaID)},
		{ID: apiInventoryObservationDataSchemaID, Version: "1.0.0", ArtifactPath: "schemas/v1/api-inventory-observation-data.schema.json", Fields: []FieldDefinition{{JSONName: "authority", GoName: "Authority", Kind: ValueString, Required: true, Enum: []string{"draft"}}, {JSONName: "validationStatus", GoName: "ValidationStatus", Kind: ValueString, Required: true, Enum: []string{"valid", "blocked"}}, token("id", "ID"), token("subjectId", "SubjectID"), token("kind", "Kind"), {JSONName: "state", GoName: "State", Kind: ValueString, Required: true, Enum: []string{"declared", "observed", "drifted", "stale", "unknown"}}, {JSONName: "observedAt", GoName: "ObservedAt", Kind: ValueString, Required: true, Nullable: true, MaxLength: intPointer(64)}, token("source", "Source")}},
		{ID: apiInventoryObservationListDataSchemaID, Version: "1.0.0", ArtifactPath: "schemas/v1/api-inventory-observation-list-data.schema.json", Fields: pageFields(apiInventoryObservationDataSchemaID)},
		{ID: apiAuditEventDataSchemaID, Version: "1.0.0", ArtifactPath: "schemas/v1/api-audit-event-data.schema.json", Fields: []FieldDefinition{
			{JSONName: "event", GoName: "Event", Kind: ValueObject, Required: true, Ref: auditEventSchemaID},
		}},
	}
}

func stateExportSchemas() []SchemaDefinition {
	token := `^[A-Za-z0-9][A-Za-z0-9._+:-]{0,127}$`
	digest := `^sha256:[0-9a-f]{64}$`
	return []SchemaDefinition{
		{ID: stateExportKindCountSchemaID, Version: "1.0.0", Fields: []FieldDefinition{
			{JSONName: "kind", GoName: "Kind", Kind: ValueString, Required: true, Enum: []string{"inventory-draft"}},
			{JSONName: "count", GoName: "Count", Kind: ValueInteger, Required: true, Minimum: int64Pointer(1), Maximum: int64Pointer(1)},
		}},
		{ID: stateExportDraftRefSchemaID, Version: "1.0.0", Fields: []FieldDefinition{
			{JSONName: "id", GoName: "ID", Kind: ValueString, Required: true, Pattern: token, MaxLength: intPointer(128)},
			{JSONName: "revision", GoName: "Revision", Kind: ValueInteger, Required: true, Minimum: int64Pointer(1)},
		}},
		{ID: stateExportSourceSchemaID, Version: "1.0.0", Fields: []FieldDefinition{
			{JSONName: "kind", GoName: "Kind", Kind: ValueString, Required: true, Pattern: token, MaxLength: intPointer(128)},
			{JSONName: "adapterKind", GoName: "AdapterKind", Kind: ValueString, Required: true, Pattern: token, MaxLength: intPointer(128)},
			{JSONName: "adapterVersion", GoName: "AdapterVersion", Kind: ValueString, Required: true, Pattern: token, MaxLength: intPointer(128)},
			{JSONName: "sourceRevision", GoName: "SourceRevision", Kind: ValueString, Required: true, MaxLength: intPointer(128)},
			{JSONName: "digest", GoName: "Digest", Kind: ValueString, Required: true, Pattern: digest},
			{JSONName: "capturedAt", GoName: "CapturedAt", Kind: ValueString, Required: true, MaxLength: intPointer(64)},
		}},
		{ID: stateExportDraftSchemaID, Version: "1.0.0", Fields: []FieldDefinition{
			{JSONName: "kind", GoName: "Kind", Kind: ValueString, Required: true, Enum: []string{"draft"}},
			{JSONName: "ref", GoName: "Ref", Kind: ValueObject, Required: true, Ref: stateExportDraftRefSchemaID},
			{JSONName: "validationStatus", GoName: "ValidationStatus", Kind: ValueString, Required: true, Enum: []string{"blocked", "valid"}},
			{JSONName: "source", GoName: "Source", Kind: ValueObject, Required: true, Ref: stateExportSourceSchemaID},
			{JSONName: "assets", GoName: "Assets", Kind: ValueArray, Required: true, ItemRef: inventoryDraftAssetSchemaID, MaxItems: intPointer(4096)},
			{JSONName: "nodes", GoName: "Nodes", Kind: ValueArray, Required: true, ItemRef: inventoryDraftNodeSchemaID, MaxItems: intPointer(4096)},
			{JSONName: "aliases", GoName: "Aliases", Kind: ValueArray, Required: true, ItemRef: inventoryDraftAliasSchemaID, MaxItems: intPointer(4096)},
			{JSONName: "addresses", GoName: "Addresses", Kind: ValueArray, Required: true, ItemRef: inventoryDraftAddressSchemaID, MaxItems: intPointer(4096)},
			{JSONName: "observations", GoName: "Observations", Kind: ValueArray, Required: true, ItemRef: inventoryDraftObservationSchemaID, MaxItems: intPointer(4096)},
			{JSONName: "provenance", GoName: "Provenance", Kind: ValueArray, Required: true, ItemRef: inventoryFieldProvenanceSchemaID, MaxItems: intPointer(32768)},
			{JSONName: "findings", GoName: "Findings", Kind: ValueArray, Required: true, ItemRef: inventoryFindingSchemaID, MaxItems: intPointer(16384)},
			{JSONName: "contentDigest", GoName: "ContentDigest", Kind: ValueString, Required: true, Pattern: digest},
		}},
		{ID: stateExportPayloadSchemaID, Version: "1.0.0", ArtifactPath: "schemas/v1/inventory-draft-snapshot-payload.schema.json", Fields: []FieldDefinition{
			{JSONName: "schema", GoName: "Schema", Kind: ValueString, Required: true, Enum: []string{stateExportPayloadSchemaID}},
			{JSONName: "schemaVersion", GoName: "SchemaVersion", Kind: ValueString, Required: true, Enum: []string{"1.0.0"}},
			{JSONName: "exportKind", GoName: "ExportKind", Kind: ValueString, Required: true, Enum: []string{"inventory-draft-snapshot"}},
			{JSONName: "subjectKind", GoName: "SubjectKind", Kind: ValueString, Required: true, Enum: []string{"draft"}},
			{JSONName: "recoveryEpoch", GoName: "RecoveryEpoch", Kind: ValueInteger, Required: true, Minimum: int64Pointer(0)},
			{JSONName: "stateRevision", GoName: "StateRevision", Kind: ValueInteger, Required: true, Minimum: int64Pointer(0)},
			{JSONName: "toolVersion", GoName: "ToolVersion", Kind: ValueString, Required: true, Pattern: token, MaxLength: intPointer(128)},
			{JSONName: "releaseBuildId", GoName: "ReleaseBuildID", Kind: ValueString, Required: true, Pattern: token, MaxLength: intPointer(128)},
			{JSONName: "sourceRevision", GoName: "SourceRevision", Kind: ValueString, Required: true, Nullable: true, Pattern: `^[0-9a-f]{40,64}$`},
			{JSONName: "contents", GoName: "Contents", Kind: ValueArray, Required: true, ItemRef: stateExportKindCountSchemaID, MinItems: intPointer(1), MaxItems: intPointer(1)},
			{JSONName: "draft", GoName: "Draft", Kind: ValueObject, Required: true, Ref: stateExportDraftSchemaID},
		}},
		{ID: stateExportSignatureSchemaID, Version: "1.0.0", ArtifactPath: "schemas/v1/inventory-draft-export-signature.schema.json", Fields: []FieldDefinition{
			{JSONName: "algorithm", GoName: "Algorithm", Kind: ValueString, Required: true, Enum: []string{"ed25519"}},
			{JSONName: "keyId", GoName: "KeyID", Kind: ValueString, Required: true, Pattern: token, MaxLength: intPointer(128)},
			{JSONName: "keyFingerprint", GoName: "KeyFingerprint", Kind: ValueString, Required: true, Pattern: digest},
			{JSONName: "value", GoName: "Value", Kind: ValueString, Required: true, Pattern: `^[A-Za-z0-9_-]{86}$`, MinLength: intPointer(86), MaxLength: intPointer(86)},
		}},
		{ID: stateExportDocumentSchemaID, Version: "1.0.0", ArtifactPath: "schemas/v1/signed-inventory-draft-export.schema.json", Fields: []FieldDefinition{
			{JSONName: "schema", GoName: "Schema", Kind: ValueString, Required: true, Enum: []string{stateExportDocumentSchemaID}},
			{JSONName: "schemaVersion", GoName: "SchemaVersion", Kind: ValueString, Required: true, Enum: []string{"1.0.0"}},
			{JSONName: "payload", GoName: "Payload", Kind: ValueObject, Required: true, Ref: stateExportPayloadSchemaID},
			{JSONName: "contentDigest", GoName: "ContentDigest", Kind: ValueString, Required: true, Pattern: digest},
			{JSONName: "signature", GoName: "Signature", Kind: ValueObject, Required: true, Ref: stateExportSignatureSchemaID},
			{JSONName: "verificationStatus", GoName: "VerificationStatus", Kind: ValueString, Required: true, Enum: []string{"verified"}},
		}},
		{ID: stateExportPointerSchemaID, Version: "1.0.0", ArtifactPath: "schemas/v1/inventory-draft-export-pointer.schema.json", Fields: []FieldDefinition{
			{JSONName: "schema", GoName: "Schema", Kind: ValueString, Required: true, Enum: []string{stateExportPointerSchemaID}},
			{JSONName: "schemaVersion", GoName: "SchemaVersion", Kind: ValueString, Required: true, Enum: []string{"1.0.0"}},
			{JSONName: "exportKind", GoName: "ExportKind", Kind: ValueString, Required: true, Enum: []string{"inventory-draft-snapshot"}},
			{JSONName: "artifactId", GoName: "ArtifactID", Kind: ValueString, Required: true, Pattern: digest},
			{JSONName: "contentDigest", GoName: "ContentDigest", Kind: ValueString, Required: true, Pattern: digest},
		}},
	}
}

func auditSchemas() []SchemaDefinition {
	tokenPattern := `^[A-Za-z0-9][A-Za-z0-9._:-]*$`
	fingerprintPattern := `^sha256:[0-9a-f]{64}$`
	return []SchemaDefinition{
		{
			ID: auditTargetSchemaID, Version: "1.0.0",
			Fields: []FieldDefinition{
				{JSONName: "kind", GoName: "Kind", Kind: ValueString, Required: true, Pattern: tokenPattern, MaxLength: intPointer(64)},
				{JSONName: "id", GoName: "ID", Kind: ValueString, Required: true, Pattern: tokenPattern, MaxLength: intPointer(128)},
			},
		},
		{
			ID: auditEventSchemaID, Version: "1.0.0", ArtifactPath: "schemas/v1/audit-event.schema.json",
			Fields: []FieldDefinition{
				{JSONName: "schema", GoName: "Schema", Kind: ValueString, Required: true, Enum: []string{auditEventSchemaID}},
				{JSONName: "schemaVersion", GoName: "SchemaVersion", Kind: ValueString, Required: true, Enum: []string{"1.0.0"}},
				{JSONName: "eventId", GoName: "EventID", Kind: ValueInteger, Required: true, Minimum: int64Pointer(1)},
				{JSONName: "occurredAt", GoName: "OccurredAt", Kind: ValueString, Required: true, MaxLength: intPointer(64)},
				{JSONName: "recoveryEpoch", GoName: "RecoveryEpoch", Kind: ValueInteger, Required: true, Minimum: int64Pointer(0)},
				{JSONName: "stateRevision", GoName: "StateRevision", Kind: ValueInteger, Required: true, Minimum: int64Pointer(0)},
				{JSONName: "type", GoName: "Type", Kind: ValueString, Required: true, Pattern: `^[a-z][a-z0-9]*(\.[a-z][a-z0-9-]*){1,5}$`, MaxLength: intPointer(96)},
				{JSONName: "correlationId", GoName: "CorrelationID", Kind: ValueString, Required: true, Pattern: tokenPattern, MaxLength: intPointer(128)},
				{JSONName: "causationEventId", GoName: "CausationEventID", Kind: ValueInteger, Required: true, Nullable: true, Minimum: int64Pointer(1)},
				{JSONName: "correctionOfEventId", GoName: "CorrectionOfEventID", Kind: ValueInteger, Required: true, Nullable: true, Minimum: int64Pointer(1)},
				{JSONName: "principalId", GoName: "PrincipalID", Kind: ValueString, Required: true, Pattern: tokenPattern, MaxLength: intPointer(128)},
				{JSONName: "principalMethod", GoName: "PrincipalMethod", Kind: ValueString, Required: true, Pattern: tokenPattern, MaxLength: intPointer(64)},
				{JSONName: "responsibleHumanPrincipalId", GoName: "ResponsibleHumanPrincipalID", Kind: ValueString, Required: true, Nullable: true, Pattern: tokenPattern, MaxLength: intPointer(128)},
				{JSONName: "agentName", GoName: "AgentName", Kind: ValueString, Required: true, Nullable: true, Pattern: tokenPattern, MaxLength: intPointer(64)},
				{JSONName: "agentSessionId", GoName: "AgentSessionID", Kind: ValueString, Required: true, Nullable: true, Pattern: tokenPattern, MaxLength: intPointer(128)},
				{JSONName: "agentSource", GoName: "AgentSource", Kind: ValueString, Required: true, Nullable: true, Enum: []string{"self-reported"}},
				{JSONName: "target", GoName: "Target", Kind: ValueObject, Required: true, Ref: auditTargetSchemaID},
				{JSONName: "beforeFingerprint", GoName: "BeforeFingerprint", Kind: ValueString, Required: true, Nullable: true, Pattern: fingerprintPattern},
				{JSONName: "afterFingerprint", GoName: "AfterFingerprint", Kind: ValueString, Required: true, Nullable: true, Pattern: fingerprintPattern},
			},
		},
		{
			ID: outboxRecordDataSchemaID, Version: "1.0.0", ArtifactPath: "schemas/v1/outbox-record-data.schema.json",
			Fields: []FieldDefinition{
				{JSONName: "outboxId", GoName: "OutboxID", Kind: ValueInteger, Required: true, Minimum: int64Pointer(1)},
				{JSONName: "eventId", GoName: "EventID", Kind: ValueInteger, Required: true, Minimum: int64Pointer(1)},
				{JSONName: "destinationId", GoName: "DestinationID", Kind: ValueString, Required: true, Pattern: tokenPattern, MaxLength: intPointer(96)},
				{JSONName: "payloadSchema", GoName: "PayloadSchema", Kind: ValueString, Required: true, Enum: []string{auditEventSchemaID}},
				{JSONName: "payloadVersion", GoName: "PayloadVersion", Kind: ValueString, Required: true, Enum: []string{"1.0.0"}},
				{JSONName: "payloadSha256", GoName: "PayloadSHA256", Kind: ValueString, Required: true, Pattern: fingerprintPattern},
				{JSONName: "dedupeSha256", GoName: "DedupeSHA256", Kind: ValueString, Required: true, Pattern: fingerprintPattern},
				{JSONName: "status", GoName: "Status", Kind: ValueString, Required: true, Enum: []string{"pending", "retry_wait", "paused", "delivered", "dead_letter"}},
				{JSONName: "attemptCount", GoName: "AttemptCount", Kind: ValueInteger, Required: true, Minimum: int64Pointer(0), Maximum: int64Pointer(8)},
				{JSONName: "maxAttempts", GoName: "MaxAttempts", Kind: ValueInteger, Required: true, Minimum: int64Pointer(8), Maximum: int64Pointer(8)},
				{JSONName: "nextAttemptAt", GoName: "NextAttemptAt", Kind: ValueString, Required: true, Nullable: true, MaxLength: intPointer(64)},
				{JSONName: "lastErrorCode", GoName: "LastErrorCode", Kind: ValueString, Required: true, Nullable: true, Enum: []string{"DESTINATION_UNAVAILABLE", "DELIVERY_REJECTED", "PAYLOAD_INVALID", "INTERRUPTED"}},
				{JSONName: "createdAt", GoName: "CreatedAt", Kind: ValueString, Required: true, MaxLength: intPointer(64)},
				{JSONName: "updatedAt", GoName: "UpdatedAt", Kind: ValueString, Required: true, MaxLength: intPointer(64)},
				{JSONName: "deliveredAt", GoName: "DeliveredAt", Kind: ValueString, Required: true, Nullable: true, MaxLength: intPointer(64)},
			},
		},
	}
}

func inventorySchemas() []SchemaDefinition {
	const (
		maxPrimary    = 4096
		maxFacts      = 16384
		maxProvenance = 32768
		maxIdentities = 64
		maxText       = 1024
	)
	token := func(jsonName, goName string, required bool) FieldDefinition {
		return FieldDefinition{JSONName: jsonName, GoName: goName, Kind: ValueString, Required: required, MaxLength: intPointer(128)}
	}
	return []SchemaDefinition{
		{
			ID:      inventoryDraftSourceSchemaID,
			Version: "1.0.0",
			Fields: []FieldDefinition{
				token("kind", "Kind", true),
				token("adapterKind", "AdapterKind", true),
				token("adapterVersion", "AdapterVersion", true),
				token("sourceRevision", "SourceRevision", true),
				{JSONName: "capturedAt", GoName: "CapturedAt", Kind: ValueString, Required: true, MaxLength: intPointer(64)},
			},
		},
		{
			ID:      inventoryDraftIdentitySchemaID,
			Version: "1.0.0",
			Fields: []FieldDefinition{
				{JSONName: "kind", GoName: "Kind", Kind: ValueString, Required: true, Enum: []string{"hardware-serial", "installation", "machine", "virtual-instance", "ssh-host-key-fingerprint"}},
				{JSONName: "value", GoName: "Value", Kind: ValueString, Required: true, MaxLength: intPointer(maxText)},
				{JSONName: "quarantined", GoName: "Quarantined", Kind: ValueBoolean, Required: true},
			},
		},
		{
			ID:      inventoryDraftHardwareFactSchemaID,
			Version: "1.0.0",
			Fields: []FieldDefinition{
				token("id", "ID", true),
				{JSONName: "kind", GoName: "Kind", Kind: ValueString, Required: true, Enum: []string{"manufacturer", "model", "chassis", "firmware-version", "cpu-architecture", "cpu-model", "cpu-physical-cores", "cpu-logical-threads", "memory-capacity", "storage-capacity"}},
				{JSONName: "integerValue", GoName: "IntegerValue", Kind: ValueInteger, Required: true, Nullable: true, Minimum: int64Pointer(0)},
				{JSONName: "textValue", GoName: "TextValue", Kind: ValueString, Required: true, Nullable: true, MaxLength: intPointer(maxText)},
				{JSONName: "unit", GoName: "Unit", Kind: ValueString, Required: true, Enum: []string{"", "bytes", "count"}},
			},
		},
		{
			ID:      inventoryDraftAssetSchemaID,
			Version: "1.0.0",
			Fields: []FieldDefinition{
				token("id", "ID", true),
				{JSONName: "kind", GoName: "Kind", Kind: ValueString, Required: true, Enum: []string{"physical", "virtual", "network", "storage", "other"}},
				{JSONName: "lifecycle", GoName: "Lifecycle", Kind: ValueString, Required: true, Enum: []string{"candidate", "available", "quarantined", "retired"}},
				{JSONName: "identities", GoName: "Identities", Kind: ValueArray, Required: true, ItemRef: inventoryDraftIdentitySchemaID, MaxItems: intPointer(maxIdentities)},
				{JSONName: "hardwareFacts", GoName: "HardwareFacts", Kind: ValueArray, Required: true, ItemRef: inventoryDraftHardwareFactSchemaID, MaxItems: intPointer(64)},
			},
		},
		{ID: inventoryDraftNodeSchemaID, Version: "1.0.0", Fields: []FieldDefinition{
			token("id", "ID", true), token("assetId", "AssetID", true), token("parentId", "ParentID", true),
		}},
		{ID: inventoryDraftAliasSchemaID, Version: "1.0.0", Fields: []FieldDefinition{
			token("id", "ID", true), token("targetId", "TargetID", true), {JSONName: "value", GoName: "Value", Kind: ValueString, Required: true, MaxLength: intPointer(maxText)},
		}},
		{ID: inventoryDraftAddressSchemaID, Version: "1.0.0", Fields: []FieldDefinition{
			token("id", "ID", true), token("nodeId", "NodeID", true), {JSONName: "value", GoName: "Value", Kind: ValueString, Required: true, MaxLength: intPointer(maxText)},
		}},
		{ID: inventoryDraftObservationSchemaID, Version: "1.0.0", Fields: []FieldDefinition{
			token("id", "ID", true), token("subjectId", "SubjectID", true), token("kind", "Kind", true), {JSONName: "value", GoName: "Value", Kind: ValueString, Required: true, MaxLength: intPointer(maxText)}, {JSONName: "observedAt", GoName: "ObservedAt", Kind: ValueString, Required: true, MaxLength: intPointer(64)},
		}},
		{ID: inventoryFieldProvenanceSchemaID, Version: "1.0.0", Fields: []FieldDefinition{
			token("recordKind", "RecordKind", true), token("recordId", "RecordID", true), {JSONName: "fieldPath", GoName: "FieldPath", Kind: ValueString, Required: true, MaxLength: intPointer(256)}, {JSONName: "locator", GoName: "Locator", Kind: ValueString, Required: true, MaxLength: intPointer(256)}, {JSONName: "capturedAt", GoName: "CapturedAt", Kind: ValueString, Required: true, MaxLength: intPointer(64)}, token("adapterVersion", "AdapterVersion", true), {JSONName: "valueStatus", GoName: "ValueStatus", Kind: ValueString, Required: true, Enum: []string{"observed", "declared", "unrecognized", "invalid"}},
		}},
		{ID: inventoryFindingSchemaID, Version: "1.0.0", Fields: []FieldDefinition{
			{JSONName: "code", GoName: "Code", Kind: ValueString, Required: true, Enum: []string{"DUPLICATE_RECORD_ID", "DUPLICATE_IDENTITY", "DUPLICATE_ALIAS", "DUPLICATE_ADDRESS", "MISSING_REFERENCE", "REFERENCE_CYCLE", "IDENTITY_CONFLICT", "IDENTITY_QUARANTINED", "IDENTITY_UNSUPPORTED", "UNSUPPORTED_VALUE", "INVALID_CAPACITY", "MISSING_REQUIRED_FIELD", "PROHIBITED_SECRET_VALUE"}}, {JSONName: "severity", GoName: "Severity", Kind: ValueString, Required: true, Enum: []string{"error"}}, {JSONName: "blocking", GoName: "Blocking", Kind: ValueBoolean, Required: true}, token("recordKind", "RecordKind", true), token("recordId", "RecordID", true), {JSONName: "fieldPath", GoName: "FieldPath", Kind: ValueString, Required: true, MaxLength: intPointer(256)}, {JSONName: "location", GoName: "Location", Kind: ValueString, Required: true, MaxLength: intPointer(256)}, {JSONName: "relatedIds", GoName: "RelatedIDs", Kind: ValueArray, Required: true, ItemKind: ValueString, MaxItems: intPointer(64), UniqueItems: true},
		}},
		{ID: inventoryDraftCountsSchemaID, Version: "1.0.0", Fields: []FieldDefinition{
			{JSONName: "assets", GoName: "Assets", Kind: ValueInteger, Required: true, Minimum: int64Pointer(0)}, {JSONName: "nodes", GoName: "Nodes", Kind: ValueInteger, Required: true, Minimum: int64Pointer(0)}, {JSONName: "aliases", GoName: "Aliases", Kind: ValueInteger, Required: true, Minimum: int64Pointer(0)}, {JSONName: "addresses", GoName: "Addresses", Kind: ValueInteger, Required: true, Minimum: int64Pointer(0)}, {JSONName: "observations", GoName: "Observations", Kind: ValueInteger, Required: true, Minimum: int64Pointer(0)}, {JSONName: "hardwareFacts", GoName: "HardwareFacts", Kind: ValueInteger, Required: true, Minimum: int64Pointer(0)}, {JSONName: "provenance", GoName: "Provenance", Kind: ValueInteger, Required: true, Minimum: int64Pointer(0)}, {JSONName: "findings", GoName: "Findings", Kind: ValueInteger, Required: true, Minimum: int64Pointer(0)},
		}},
		{
			ID: inventoryDraftInputSchemaID, Version: "1.0.0", ArtifactPath: "schemas/v1/inventory-draft-input.schema.json",
			Fields: []FieldDefinition{
				{JSONName: "schema", GoName: "Schema", Kind: ValueString, Required: true, Enum: []string{inventoryDraftInputSchemaID}},
				{JSONName: "schemaVersion", GoName: "SchemaVersion", Kind: ValueString, Required: true, Enum: []string{"1.0.0"}},
				{JSONName: "source", GoName: "Source", Kind: ValueObject, Required: true, Ref: inventoryDraftSourceSchemaID},
				{JSONName: "assets", GoName: "Assets", Kind: ValueArray, Required: true, ItemRef: inventoryDraftAssetSchemaID, MaxItems: intPointer(maxPrimary)},
				{JSONName: "nodes", GoName: "Nodes", Kind: ValueArray, Required: true, ItemRef: inventoryDraftNodeSchemaID, MaxItems: intPointer(maxPrimary)},
				{JSONName: "aliases", GoName: "Aliases", Kind: ValueArray, Required: true, ItemRef: inventoryDraftAliasSchemaID, MaxItems: intPointer(maxPrimary)},
				{JSONName: "addresses", GoName: "Addresses", Kind: ValueArray, Required: true, ItemRef: inventoryDraftAddressSchemaID, MaxItems: intPointer(maxPrimary)},
				{JSONName: "observations", GoName: "Observations", Kind: ValueArray, Required: true, ItemRef: inventoryDraftObservationSchemaID, MaxItems: intPointer(maxPrimary)},
				{JSONName: "provenance", GoName: "Provenance", Kind: ValueArray, Required: true, ItemRef: inventoryFieldProvenanceSchemaID, MaxItems: intPointer(maxProvenance)},
			},
		},
		{
			ID: inventoryImportDataSchemaID, Version: "1.0.0", ArtifactPath: "schemas/v1/inventory-import-data.schema.json",
			Fields: []FieldDefinition{
				token("draftId", "DraftID", true), {JSONName: "draftRevision", GoName: "DraftRevision", Kind: ValueInteger, Required: true, Minimum: int64Pointer(1)}, {JSONName: "validationStatus", GoName: "ValidationStatus", Kind: ValueString, Required: true, Enum: []string{"valid", "blocked"}}, {JSONName: "sourceDigest", GoName: "SourceDigest", Kind: ValueString, Required: true, Pattern: `^sha256:[0-9a-f]{64}$`}, {JSONName: "contentDigest", GoName: "ContentDigest", Kind: ValueString, Required: true, Pattern: `^sha256:[0-9a-f]{64}$`}, {JSONName: "stateRevision", GoName: "StateRevision", Kind: ValueInteger, Required: true, Minimum: int64Pointer(0)}, {JSONName: "recoveryEpoch", GoName: "RecoveryEpoch", Kind: ValueInteger, Required: true, Minimum: int64Pointer(0)}, {JSONName: "eventId", GoName: "EventID", Kind: ValueInteger, Required: true, Minimum: int64Pointer(1)}, {JSONName: "created", GoName: "Created", Kind: ValueBoolean, Required: true}, {JSONName: "counts", GoName: "Counts", Kind: ValueObject, Required: true, Ref: inventoryDraftCountsSchemaID}, {JSONName: "findings", GoName: "Findings", Kind: ValueArray, Required: true, ItemRef: inventoryFindingSchemaID, MaxItems: intPointer(maxFacts)},
			},
		},
	}
}

func int64Pointer(value int64) *int64 { return &value }

func intPointer(value int) *int { return &value }

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
