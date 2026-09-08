package contractgen

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/metadata"
)

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
		"internal/generated/contracts_gen.go",
		"schemas/v1/command-registry.json",
		"schemas/v1/command-registry.schema.json",
		"schemas/v1/database-status-data.schema.json",
		"schemas/v1/release-inspect-data.schema.json",
		"schemas/v1/release-manifest.schema.json",
		"schemas/v1/release-trust-policy.schema.json",
		"schemas/v1/release-verify-data.schema.json",
		"schemas/v1/run-result.schema.json",
		"schemas/v1/server-profile.schema.json",
		"schemas/v1/server-status-data.schema.json",
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
	if available != 6 || planned != 45 {
		t.Fatalf("command availability = (%d available, %d planned), want (6, 45)", available, planned)
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
		`= "1.2.0"`,
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
		`type ServerProfile struct`,
		`type ServerStatusData struct`,
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
