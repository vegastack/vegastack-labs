package contractgen

import (
	"bytes"
	"encoding/json"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/metadata"
)

func TestGeneratedPhase4StatesMatchEveryTarget(t *testing.T) {
	t.Parallel()

	artifacts, err := Generate(metadata.Current())
	if err != nil {
		t.Fatal(err)
	}
	byPath := make(map[string]string, len(artifacts))
	for _, artifact := range artifacts {
		byPath[artifact.Path] = string(artifact.Content)
	}
	for _, path := range []string{
		"internal/generated/contracts_gen.go",
		"internal/generated/contracts_validate_gen.go",
		"web/generated/read-api.ts",
		"docs/generated/cli-reference.md",
		"docs/generated/api-reference.md",
	} {
		content, ok := byPath[path]
		if !ok {
			t.Errorf("generated artifact %s is missing", path)
			continue
		}
		for _, value := range []string{"partial", "interrupted", "cancelled", "leaseExpiresAt", "planDigest"} {
			if !strings.Contains(content, value) {
				t.Errorf("%s is missing %q", path, value)
			}
		}
	}
	client := byPath["web/generated/read-api.ts"]
	for _, method := range []string{"createPlan", "getPlan", "executePlan", "getRun", "cancelRun", "resumeRun"} {
		if !strings.Contains(client, method) {
			t.Errorf("browser client is missing %s", method)
		}
	}
}

func TestGenerateIsByteStable(t *testing.T) {
	t.Parallel()

	first, err := Generate(metadata.Current())
	if err != nil {
		t.Fatal(err)
	}
	second, err := Generate(metadata.Current())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatal("Generate() returned different bytes for identical metadata")
	}

	wantPaths := []string{
		"docs/generated/command-registry.md",
		"docs/generated/endpoint-registry.md",
		"internal/generated/contracts_gen.go",
		"internal/generated/contracts_validate_gen.go",
		"schemas/v1/command-registry.json",
		"schemas/v1/command-registry.schema.json",
		"schemas/v1/endpoint-registry.json",
		"schemas/v1/endpoint-registry.schema.json",
		"web/generated/read-api.ts",
		"docs/generated/cli-reference.md",
		"docs/generated/api-reference.md",
		"schemas/v1/acknowledgement-request.schema.json",
		"schemas/v1/acknowledgement.schema.json",
		"schemas/v1/api-audit-event-data.schema.json",
		"schemas/v1/api-browser-session-data.schema.json",
		"schemas/v1/api-browser-session-request.schema.json",
		"schemas/v1/api-inventory-alias-data.schema.json",
		"schemas/v1/api-inventory-alias-list-data.schema.json",
		"schemas/v1/api-inventory-asset-data.schema.json",
		"schemas/v1/api-inventory-asset-list-data.schema.json",
		"schemas/v1/api-inventory-draft-data.schema.json",
		"schemas/v1/api-inventory-draft-list-data.schema.json",
		"schemas/v1/api-inventory-node-data.schema.json",
		"schemas/v1/api-inventory-node-list-data.schema.json",
		"schemas/v1/api-inventory-observation-data.schema.json",
		"schemas/v1/api-inventory-observation-list-data.schema.json",
		"schemas/v1/api-page-data.schema.json",
		"schemas/v1/api-source-counts-data.schema.json",
		"schemas/v1/api-source-data.schema.json",
		"schemas/v1/api-source-list-data.schema.json",
		"schemas/v1/api-source-list-query.schema.json",
		"schemas/v1/api-summary-data.schema.json",
		"schemas/v1/audit-event.schema.json",
		"schemas/v1/authorization-decision.schema.json",
		"schemas/v1/cloudflare-access-profile.schema.json",
		"schemas/v1/database-status-data.schema.json",
		"schemas/v1/declaration-revision-request.schema.json",
		"schemas/v1/declaration-revision.schema.json",
		"schemas/v1/execution-receipt-request.schema.json",
		"schemas/v1/execution-receipt.schema.json",
		"schemas/v1/executor-claim-request.schema.json",
		"schemas/v1/executor-lease.schema.json",
		"schemas/v1/executor-renew-request.schema.json",
		"schemas/v1/inventory-diff-data.schema.json",
		"schemas/v1/inventory-diff-request.schema.json",
		"schemas/v1/inventory-draft-export-pointer.schema.json",
		"schemas/v1/inventory-draft-export-signature.schema.json",
		"schemas/v1/inventory-draft-input.schema.json",
		"schemas/v1/inventory-draft-snapshot-payload.schema.json",
		"schemas/v1/inventory-export-data.schema.json",
		"schemas/v1/inventory-export-request.schema.json",
		"schemas/v1/inventory-import-data.schema.json",
		"schemas/v1/inventory-import-request.schema.json",
		"schemas/v1/outbox-record-data.schema.json",
		"schemas/v1/plan-create-request.schema.json",
		"schemas/v1/plan-reference-request.schema.json",
		"schemas/v1/plan.schema.json",
		"schemas/v1/release-inspect-data.schema.json",
		"schemas/v1/release-manifest.schema.json",
		"schemas/v1/release-trust-policy.schema.json",
		"schemas/v1/release-verify-data.schema.json",
		"schemas/v1/run-reference-request.schema.json",
		"schemas/v1/run-result.schema.json",
		"schemas/v1/run.schema.json",
		"schemas/v1/server-profile.schema.json",
		"schemas/v1/server-status-data.schema.json",
		"schemas/v1/signed-inventory-draft-export.schema.json",
	}
	gotPaths := make([]string, len(first))
	for index, artifact := range first {
		gotPaths[index] = artifact.Path
		if !bytes.HasSuffix(artifact.Content, []byte("\n")) {
			t.Errorf("%s has no trailing LF", artifact.Path)
		}
		if bytes.Contains(artifact.Content, []byte("\r\n")) {
			t.Errorf("%s contains CRLF", artifact.Path)
		}
	}
	if !reflect.DeepEqual(gotPaths, wantPaths) {
		t.Fatalf("artifact paths = %v, want %v", gotPaths, wantPaths)
	}
}

func TestGenerateSelectsOnlyBrowserSafeAvailableReads(t *testing.T) {
	t.Parallel()

	artifacts, err := Generate(metadata.Current())
	if err != nil {
		t.Fatal(err)
	}
	byPath := make(map[string][]byte, len(artifacts))
	for _, artifact := range artifacts {
		byPath[artifact.Path] = artifact.Content
	}
	client := string(byPath["web/generated/read-api.ts"])
	for _, forbidden := range []string{"inventory-drafts.import", "http://", "https://", "/var/", "SELECT ", "apiToken", "secretValue"} {
		if strings.Contains(client, forbidden) {
			t.Fatalf("unsafe value %q entered browser client", forbidden)
		}
	}
	if !strings.Contains(client, "api.v1.events.stream") || !strings.Contains(client, "api.v1.summary.get") {
		t.Fatal("implemented reads missing")
	}
}

func TestGenerateEmitsSecretFreeBrowserSessionContracts(t *testing.T) {
	t.Parallel()

	artifacts, err := Generate(metadata.Current())
	if err != nil {
		t.Fatal(err)
	}
	byPath := make(map[string][]byte, len(artifacts))
	for _, artifact := range artifacts {
		byPath[artifact.Path] = artifact.Content
	}
	for _, path := range []string{"schemas/v1/api-browser-session-request.schema.json", "schemas/v1/api-browser-session-data.schema.json"} {
		var schema map[string]any
		if err := json.Unmarshal(byPath[path], &schema); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if schema["additionalProperties"] != false {
			t.Fatalf("%s is open", path)
		}
	}
	generatedGo := string(byPath["internal/generated/contracts_gen.go"])
	if !strings.Contains(generatedGo, "type ApiBrowserSessionData struct") || !strings.Contains(generatedGo, "type ApiBrowserSessionRequest struct") {
		t.Fatal("generated session types are missing")
	}
	if regexp.MustCompile(`(?i)type ApiBrowserSessionData[\\s\\S]{0,500}(jwt|cookie|email|claim|secret|token)`).MatchString(generatedGo) {
		t.Fatal("generated session data contains a private field")
	}
}

func TestGenerateRejectsSecretShapedBrowserSchema(t *testing.T) {
	t.Parallel()

	for _, name := range []string{
		"apiToken", "apiKey", "API_KEY", "accessKey", "Access-Key", "privateKeyMaterial",
		"bearer", "Authorization", "authHeader", "cookie", "Set-Cookie", "sessionCookie", "clientSecret",
	} {
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			registry := browserTestRegistry(metadata.SchemaDefinition{
				ID: "vegastack-labs.dev/unsafe-browser-data", Version: "1.0.0",
				Fields: []metadata.FieldDefinition{{JSONName: name, GoName: "Sensitive", Kind: metadata.ValueString, Required: true}},
			})
			assertUnsafeBrowserSchema(t, registry)
		})
	}
}

func TestGenerateRejectsNestedAndOpenBrowserSchemas(t *testing.T) {
	t.Parallel()

	t.Run("nested secret", func(t *testing.T) {
		registry := browserTestRegistry(
			metadata.SchemaDefinition{
				ID: "vegastack-labs.dev/unsafe-browser-data", Version: "1.0.0",
				Fields: []metadata.FieldDefinition{{JSONName: "details", GoName: "Details", Kind: metadata.ValueObject, Required: true, Ref: "vegastack-labs.dev/unsafe-browser-details"}},
			},
			metadata.SchemaDefinition{
				ID: "vegastack-labs.dev/unsafe-browser-details", Version: "1.0.0",
				Fields: []metadata.FieldDefinition{{JSONName: "authorization", GoName: "Authorization", Kind: metadata.ValueString, Required: true}},
			},
		)
		assertUnsafeBrowserSchema(t, registry)
	})

	t.Run("open object", func(t *testing.T) {
		registry := browserTestRegistry(metadata.SchemaDefinition{
			ID: "vegastack-labs.dev/unsafe-browser-data", Version: "1.0.0",
			Fields: []metadata.FieldDefinition{{JSONName: "headers", GoName: "Headers", Kind: metadata.ValueObject, Required: true, AdditionalProperties: true}},
		})
		assertUnsafeBrowserSchema(t, registry)
	})
}

func TestGenerateAllowsSafeKeyIdentifiersInBrowserSchema(t *testing.T) {
	t.Parallel()

	registry := browserTestRegistry(metadata.SchemaDefinition{
		ID: "vegastack-labs.dev/unsafe-browser-data", Version: "1.0.0",
		Fields: []metadata.FieldDefinition{
			{JSONName: "keyId", GoName: "KeyID", Kind: metadata.ValueString, Required: true},
			{JSONName: "keyFingerprint", GoName: "KeyFingerprint", Kind: metadata.ValueString, Required: true},
			{JSONName: "publicKeyId", GoName: "PublicKeyID", Kind: metadata.ValueString, Required: true},
			{JSONName: "idempotencyKey", GoName: "IdempotencyKey", Kind: metadata.ValueString, Required: true},
		},
	})
	if _, err := Generate(registry); err != nil {
		t.Fatalf("Generate() rejected safe key identifiers: %v", err)
	}
}

func browserTestRegistry(schemas ...metadata.SchemaDefinition) metadata.Registry {
	registry := metadata.Current()
	registry.Schemas = append(registry.Schemas, schemas...)
	registry.Endpoints = append(registry.Endpoints, metadata.EndpointDefinition{
		ID: "api.v1.unsafe.get", Method: "GET", Path: "/api/v1/unsafe", Availability: metadata.AvailabilityAvailable,
		OwnerPhase: "2", DataSchema: "vegastack-labs.dev/unsafe-browser-data", Stream: metadata.StreamFinite, Audiences: []metadata.EndpointAudience{metadata.AudienceBrowser},
	})
	return registry
}

func assertUnsafeBrowserSchema(t *testing.T, registry metadata.Registry) {
	t.Helper()
	_, err := Generate(registry)
	if err == nil || !strings.Contains(err.Error(), "GENERATED_BROWSER_SCHEMA_UNSAFE") {
		t.Fatalf("Generate() error = %v", err)
	}
}

func TestGenerateBrowserClientHasStrictTypesAndDecoders(t *testing.T) {
	t.Parallel()

	artifacts, err := Generate(metadata.Current())
	if err != nil {
		t.Fatal(err)
	}
	var client string
	for _, artifact := range artifacts {
		if artifact.Path == browserClientPath {
			client = string(artifact.Content)
		}
	}
	for _, want := range []string{
		"export interface ApiSummaryData",
		"export type ApiFailureKind",
		"export type StableErrorCode",
		"export const STABLE_ERROR_CODES",
		"export class ReadClientError",
		"function decodeApiSummaryData",
		"export type ReadEnvelope",
		"schemaVersion: canonicalVersion",
		"additional property",
		"unsupported-version",
	} {
		if !strings.Contains(client, want) {
			t.Errorf("browser client missing %q", want)
		}
	}
	for _, forbidden := range []string{"SCHEMA_MISMATCH", "MALFORMED_JSON", "readonly code: string"} {
		if strings.Contains(client, forbidden) {
			t.Errorf("browser client contains non-canonical error declaration %q", forbidden)
		}
	}
}

func TestGenerateEmitsStrictSourceHealthContracts(t *testing.T) {
	t.Parallel()

	artifacts, err := Generate(metadata.Current())
	if err != nil {
		t.Fatal(err)
	}
	byPath := make(map[string][]byte, len(artifacts))
	for _, artifact := range artifacts {
		byPath[artifact.Path] = artifact.Content
	}
	for _, path := range []string{
		"schemas/v1/api-source-data.schema.json",
		"schemas/v1/api-source-list-data.schema.json",
		"schemas/v1/api-source-counts-data.schema.json",
		"schemas/v1/api-source-list-query.schema.json",
	} {
		var schema map[string]any
		if err := json.Unmarshal(byPath[path], &schema); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if schema["additionalProperties"] != false {
			t.Fatalf("%s is open", path)
		}
	}
	generatedGo := string(byPath["internal/generated/contracts_gen.go"])
	for _, declaration := range []string{"type ApiSourceData struct", "type ApiSourceListData struct", "type ApiSourceCountsData struct", "type ApiSourceListQuery struct"} {
		if !strings.Contains(generatedGo, declaration) {
			t.Errorf("missing %q", declaration)
		}
	}
	client := string(byPath["web/generated/read-api.ts"])
	for _, declaration := range []string{"export interface ApiSourceData", "export interface ApiSourceListData", "export interface ApiSourceListQuery", "readonly listSources:", "decodeApiSourceListData", "sourceListQuery(query)"} {
		if !strings.Contains(client, declaration) {
			t.Errorf("browser client missing %q", declaration)
		}
	}
}

func TestGenerateEmitsInventoryArtifactsAndClosedInput(t *testing.T) {
	t.Parallel()

	artifacts, err := Generate(metadata.Current())
	if err != nil {
		t.Fatal(err)
	}
	byPath := map[string][]byte{}
	for _, artifact := range artifacts {
		byPath[artifact.Path] = artifact.Content
	}
	raw := byPath["schemas/v1/inventory-draft-input.schema.json"]
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	if schema["additionalProperties"] != false {
		t.Fatalf("inventory input additionalProperties = %v", schema["additionalProperties"])
	}
	generatedGo := string(byPath["internal/generated/contracts_gen.go"])
	for _, declaration := range []string{
		"type InventoryDraftInput struct",
		"type InventoryImportData struct",
		"type InventoryDraftAsset struct",
		"type InventoryFieldProvenance struct",
	} {
		if !strings.Contains(generatedGo, declaration) {
			t.Errorf("missing %q", declaration)
		}
	}
}

func TestGenerateEmitsStrictInventoryOperationSchemas(t *testing.T) {
	t.Parallel()

	artifacts, err := Generate(metadata.Current())
	if err != nil {
		t.Fatal(err)
	}
	byPath := make(map[string][]byte, len(artifacts))
	for _, artifact := range artifacts {
		byPath[artifact.Path] = artifact.Content
	}
	for _, path := range []string{
		"schemas/v1/inventory-import-request.schema.json",
		"schemas/v1/inventory-diff-request.schema.json",
		"schemas/v1/inventory-export-data.schema.json",
	} {
		var schema map[string]any
		if err := json.Unmarshal(byPath[path], &schema); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if schema["additionalProperties"] != false {
			t.Fatalf("%s is open", path)
		}
	}
	generatedGo := string(byPath["internal/generated/contracts_gen.go"])
	for _, declaration := range []string{"type InventoryImportRequest struct", "type InventoryDiffData struct", "type InventoryExportData struct"} {
		if !strings.Contains(generatedGo, declaration) {
			t.Errorf("missing %q", declaration)
		}
	}
}

func TestGenerateEmitsClosedAuditArtifactsAndTypes(t *testing.T) {
	t.Parallel()

	artifacts, err := Generate(metadata.Current())
	if err != nil {
		t.Fatal(err)
	}
	byPath := map[string][]byte{}
	for _, artifact := range artifacts {
		byPath[artifact.Path] = artifact.Content
	}
	for _, path := range []string{"schemas/v1/audit-event.schema.json", "schemas/v1/outbox-record-data.schema.json"} {
		var schema map[string]any
		if err := json.Unmarshal(byPath[path], &schema); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if schema["additionalProperties"] != false {
			t.Fatalf("%s additionalProperties = %v", path, schema["additionalProperties"])
		}
	}
	var auditSchema struct {
		Properties map[string]struct {
			Enum []any `json:"enum"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(byPath["schemas/v1/audit-event.schema.json"], &auditSchema); err != nil {
		t.Fatal(err)
	}
	agentSource := auditSchema.Properties["agentSource"].Enum
	if len(agentSource) != 2 || agentSource[0] != nil || agentSource[1] != "self-reported" {
		t.Fatalf("nullable enum excludes null: %#v", agentSource)
	}
	generatedGo := string(byPath["internal/generated/contracts_gen.go"])
	for _, declaration := range []string{"type AuditEvent struct", "type AuditTarget struct", "type OutboxRecordData struct"} {
		if !strings.Contains(generatedGo, declaration) {
			t.Errorf("missing %q", declaration)
		}
	}
}

func TestGeneratedContractsPreservePublicBoundary(t *testing.T) {
	t.Parallel()

	artifacts, err := Generate(metadata.Current())
	if err != nil {
		t.Fatal(err)
	}
	byPath := make(map[string][]byte, len(artifacts))
	for _, artifact := range artifacts {
		byPath[artifact.Path] = artifact.Content
	}

	var runSchema map[string]any
	if err := json.Unmarshal(byPath["schemas/v1/run-result.schema.json"], &runSchema); err != nil {
		t.Fatal(err)
	}
	if runSchema["$schema"] != "https://json-schema.org/draft/2020-12/schema" {
		t.Fatalf("JSON Schema dialect = %v", runSchema["$schema"])
	}
	if runSchema["additionalProperties"] != false {
		t.Fatalf("run-result additionalProperties = %v", runSchema["additionalProperties"])
	}
	properties := runSchema["properties"].(map[string]any)
	for _, field := range []string{
		"schema", "schemaVersion", "toolVersion", "command", "requestId", "runId",
		"status", "changed", "recoveryEpoch", "stateRevision", "snapshotDigest",
		"releaseBuildId", "sourceRevision", "planId", "errors", "data",
	} {
		if _, ok := properties[field]; !ok {
			t.Errorf("run-result property %q is missing", field)
		}
	}
	if _, ok := properties["provider"]; ok {
		t.Fatal("run-result exposes provider-specific field")
	}
	var registrySchema map[string]any
	if err := json.Unmarshal(byPath["schemas/v1/command-registry.schema.json"], &registrySchema); err != nil {
		t.Fatal(err)
	}
	registryProperties := registrySchema["properties"].(map[string]any)
	commandsSchema := registryProperties["commands"].(map[string]any)
	commandItem := commandsSchema["items"].(map[string]any)
	if rules, ok := commandItem["allOf"].([]any); !ok || len(rules) != 2 {
		t.Fatalf("command availability rules = %#v, want planned and available guards", commandItem["allOf"])
	}
	flagItem := commandItem["properties"].(map[string]any)["flags"].(map[string]any)["items"].(map[string]any)
	if rules, ok := flagItem["allOf"].([]any); !ok || len(rules) != 2 {
		t.Fatalf("flag kind rules = %#v, want switch and value guards", flagItem["allOf"])
	}

	var registry struct {
		GeneratedBy string `json:"generatedBy"`
		Commands    []struct {
			Path         []string `json:"path"`
			Availability string   `json:"availability"`
			Risk         string   `json:"risk"`
			Flags        []any    `json:"flags"`
			Request      string   `json:"requestSchema"`
			Result       string   `json:"resultSchema"`
			Examples     []any    `json:"examples"`
		} `json:"commands"`
	}
	if err := json.Unmarshal(byPath["schemas/v1/command-registry.json"], &registry); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(registry.GeneratedBy, "DO NOT EDIT") {
		t.Fatalf("generatedBy = %q", registry.GeneratedBy)
	}
	available, planned := 0, 0
	for _, command := range registry.Commands {
		switch command.Availability {
		case "available":
			available++
		case "planned":
			planned++
			if command.Risk != "unassigned" || len(command.Flags) != 0 || command.Request != "" || command.Result != "" || len(command.Examples) != 0 {
				t.Fatalf("planned command %v contains speculative detail", command.Path)
			}
		}
	}
	if available != 11 || planned != 40 {
		t.Fatalf("command availability = (%d available, %d planned), want (11, 40)", available, planned)
	}

	for _, path := range []string{
		"docs/generated/command-registry.md",
		"internal/generated/contracts_gen.go",
		"schemas/v1/command-registry.schema.json",
		"schemas/v1/run-result.schema.json",
	} {
		if !bytes.Contains(byPath[path], []byte("DO NOT EDIT")) {
			t.Errorf("%s lacks a do-not-edit marker", path)
		}
	}
}

func TestGeneratedGoIsRuntimeSerializable(t *testing.T) {
	t.Parallel()

	artifacts, err := Generate(metadata.Current())
	if err != nil {
		t.Fatal(err)
	}
	var source []byte
	for _, artifact := range artifacts {
		if artifact.Path == "internal/generated/contracts_gen.go" {
			source = artifact.Content
			break
		}
	}
	for _, want := range []string{
		`RegistrySchemaVersion`,
		`= "1.10.0"`,
		`type Endpoint struct`,
		`var Endpoints = []Endpoint`,
		`type DatabaseStatusData struct`,
		`SchemaIDRunResult`,
		`SchemaIDResultError`,
		`AvailabilityAvailable`,
		`AvailabilityPlanned`,
		`json:"path"`,
		`json:"flags,omitempty"`,
		`json:"arguments"`,
		`type ReleaseManifest struct`,
		`type ReleaseAsset struct`,
		`type ReleaseTrustPolicy struct`,
		`type ReleaseInspectData struct`,
		`type ReleaseVerifyData struct`,
		`type ReleaseAssetVerification struct`,
		`type LocalPrincipalBinding struct`,
		`type RemoteReadProfile struct`,
		`type CloudflareAccessProfile struct`,
		`type ServerProfile struct`,
		`type ServerStatusData struct`,
		`type InventoryDraftSnapshotPayload struct`,
		`type InventoryDraftExportSignature struct`,
		`type SignedInventoryDraftExport struct`,
		`type InventoryDraftExportPointer struct`,
		`CommandNameServerRun`,
		`CommandNameServerStatus`,
		`FlagConfig`,
		`FlagManifest`,
		`FlagPolicy`,
		`FlagAsset`,
		`FlagAll`,
	} {
		if !bytes.Contains(source, []byte(want)) {
			t.Errorf("generated Go is missing %q", want)
		}
	}
	for _, definition := range metadata.Current().Errors {
		want := "ErrorCode" + errorCodeGoName(definition.Code)
		if !bytes.Contains(source, []byte(want)) {
			t.Errorf("generated Go is missing %q", want)
		}
	}
}

func TestGenerateDoesNotLeakRejectedMetadata(t *testing.T) {
	t.Parallel()

	registry := metadata.Current()
	secret := "private-generator-canary"
	duplicate := registry.Commands[0]
	duplicate.Summary = secret
	registry.Commands = append(registry.Commands, duplicate)
	_, err := Generate(registry)
	if err == nil {
		t.Fatal("Generate() error = nil")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("Generate() leaked rejected metadata: %q", err)
	}
}
