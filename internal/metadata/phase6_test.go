package metadata

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

// Phase 6 adds host identity, role, role-alias, OS-profile and host-hardening
// evidence contracts, plus host hardening/role-admission gate definitions. The
// core stays provider-neutral; the concrete role/OS values are Labs
// deployment-profile shapes. These are inert public shapes; they assert no admission.

func TestPhase6HostSchemasRegistered(t *testing.T) {
	reg := Current()
	present := map[string]bool{}
	for _, s := range reg.Schemas {
		present[s.ID] = true
	}
	for _, id := range []string{
		"vegastack-labs.dev/host-identity",
		"vegastack-labs.dev/host-role",
		"vegastack-labs.dev/host-role-alias",
		"vegastack-labs.dev/host-profile",
		"vegastack-labs.dev/host-hardening-evidence-fact",
	} {
		if !present[id] {
			t.Fatalf("unknown schema %s", id)
		}
	}
	if err := Validate(reg); err != nil {
		t.Fatalf("registry invalid after phase 6 schemas: %v", err)
	}
}

func TestPhase6HostGatesDefined(t *testing.T) {
	defs := map[string]GateDefinitionSource{}
	for _, d := range CurrentGateDefinitions() {
		defs[d.GateID] = d
	}
	hardening, ok := defs["host.hardening-baseline"]
	if !ok {
		t.Fatalf("gate host.hardening-baseline not found")
	}
	if len(hardening.SubjectKinds) != 1 || hardening.SubjectKinds[0] != "node" {
		t.Fatalf("hardening gate must apply to node subjects, got %v", hardening.SubjectKinds)
	}
	if hardening.Applicability != "always" || hardening.DefinitionVersion != "1.1.0" || hardening.EvidenceSchemaID != gateEvidenceSchemaID {
		t.Fatalf("hardening gate must use the exact host evaluator version: %+v", hardening)
	}
	admission, ok := defs["host.role-admission"]
	if !ok {
		t.Fatalf("gate host.role-admission not found")
	}
	if !phase6Contains(admission.PrerequisiteGateIDs, "host.hardening-baseline") {
		t.Fatalf("role-admission must require hardening baseline, got %v", admission.PrerequisiteGateIDs)
	}
	if admission.Applicability != "always" || admission.DefinitionVersion != "1.1.0" || admission.EvidenceSchemaID != gateEvidenceSchemaID {
		t.Fatalf("role-admission must use the exact host evaluator version: %+v", admission)
	}
}

// The host-hardening-evidence-fact schema is the fact content a downstream
// hardening/admission proof (Issue 6.8) carries inside the standard gate-evidence
// envelope. It is a delivered contract here, so prove it validates well-formed
// content and fails closed on a malformed/undated fact.
func TestPhase6HostHardeningEvidenceFactValidates(t *testing.T) {
	fact := generated.HostHardeningEvidenceFact{
		Schema: generated.SchemaIDHostHardeningEvidenceFact, SchemaVersion: "1.0.0",
		HostID: "node-a", ProfileID: "debian-13-amd64", OSFamily: "debian",
		OSVersion: "13.6", Architecture: "amd64", RoleID: "control",
		BaselineVersion: "1.0.0", ControlsPassed: 11, ControlsTotal: 11,
		ResultDigest: "sha256:" + strings.Repeat("a", 64),
		ObservedAt:   "2026-09-16T00:00:00Z", RecoveryEpoch: 0,
	}
	raw, err := json.Marshal(fact)
	if err != nil {
		t.Fatal(err)
	}
	if err := generated.ValidateContractJSON(generated.SchemaIDHostHardeningEvidenceFact, raw, generated.ContractExact); err != nil {
		t.Fatalf("well-formed hardening fact rejected: %v", err)
	}
	build := "25A354"
	macFact := fact
	macFact.ProfileID, macFact.OSFamily, macFact.OSVersion = "macos-current-arm64", "macos", "26.0"
	macFact.OSBuild, macFact.Architecture, macFact.RoleID = &build, "arm64", "hermes"
	raw, err = json.Marshal(macFact)
	if err != nil {
		t.Fatal(err)
	}
	if err := generated.ValidateContractJSON(generated.SchemaIDHostHardeningEvidenceFact, raw, generated.ContractExact); err != nil {
		t.Fatalf("exact Mac build and role fact rejected: %v", err)
	}
	missingRole := map[string]any{}
	if err := json.Unmarshal(raw, &missingRole); err != nil {
		t.Fatal(err)
	}
	delete(missingRole, "roleId")
	raw, err = json.Marshal(missingRole)
	if err != nil {
		t.Fatal(err)
	}
	if err := generated.ValidateContractJSON(generated.SchemaIDHostHardeningEvidenceFact, raw, generated.ContractExact); err == nil {
		t.Fatal("hardening fact without its role accepted")
	}
	undated := fact
	undated.ObservedAt = "not-a-timestamp"
	raw, _ = json.Marshal(undated)
	if err := generated.ValidateContractJSON(generated.SchemaIDHostHardeningEvidenceFact, raw, generated.ContractExact); err == nil {
		t.Fatal("malformed/undated hardening fact accepted")
	}
}

func TestPhase6HostProfileCarriesExactMacBuild(t *testing.T) {
	build := "25A354"
	profile := generated.HostProfile{
		Schema: generated.SchemaIDHostProfile, SchemaVersion: "1.0.0",
		ProfileID: "macos-current-arm64", OSFamily: "macos", OSVersion: "26.0",
		OSBuild: &build, Architecture: "arm64", RoleID: "hermes", DefinitionVersion: "1.0.0",
	}
	raw, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	if err := generated.ValidateContractJSON(generated.SchemaIDHostProfile, raw, generated.ContractExact); err != nil {
		t.Fatalf("exact Mac build rejected: %v", err)
	}
	missingBuild := map[string]any{}
	if err := json.Unmarshal(raw, &missingBuild); err != nil {
		t.Fatal(err)
	}
	delete(missingBuild, "osBuild")
	missingRaw, err := json.Marshal(missingBuild)
	if err != nil {
		t.Fatal(err)
	}
	if err := generated.ValidateContractJSON(generated.SchemaIDHostProfile, missingRaw, generated.ContractExact); err == nil {
		t.Fatal("host profile without an explicit build field accepted")
	}
	profile.OSBuild = nil
	profile.OSFamily, profile.ProfileID, profile.OSVersion, profile.Architecture, profile.RoleID = "debian", "debian-13-amd64", "13.6", "amd64", "control"
	raw, err = json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	if err := generated.ValidateContractJSON(generated.SchemaIDHostProfile, raw, generated.ContractExact); err != nil {
		t.Fatalf("explicit null Debian build rejected: %v", err)
	}
	badBuild := "25A354/other"
	profile.OSBuild = &badBuild
	raw, err = json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	if err := generated.ValidateContractJSON(generated.SchemaIDHostProfile, raw, generated.ContractExact); err == nil {
		t.Fatal("invalid build identifier accepted")
	}
}

func phase6Contains(values []string, target string) bool {
	for _, v := range values {
		if v == target {
			return true
		}
	}
	return false
}
