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
	admission, ok := defs["host.role-admission"]
	if !ok {
		t.Fatalf("gate host.role-admission not found")
	}
	if !phase6Contains(admission.PrerequisiteGateIDs, "host.hardening-baseline") {
		t.Fatalf("role-admission must require hardening baseline, got %v", admission.PrerequisiteGateIDs)
	}
}

// The host-hardening-evidence-fact schema is the fact content a downstream
// hardening/admission proof (Issue 6.8) carries inside the standard gate-evidence
// envelope. It is a delivered contract here, so prove it validates well-formed
// content and fails closed on a malformed/undated fact.
func TestPhase6HostHardeningEvidenceFactValidates(t *testing.T) {
	fact := generated.HostHardeningEvidenceFact{
		Schema: generated.SchemaIDHostHardeningEvidenceFact, SchemaVersion: "1.0.0",
		HostID: "node-a", ProfileID: "vegastack-labs", OSFamily: "debian",
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
	undated := fact
	undated.ObservedAt = "not-a-timestamp"
	raw, _ = json.Marshal(undated)
	if err := generated.ValidateContractJSON(generated.SchemaIDHostHardeningEvidenceFact, raw, generated.ContractExact); err == nil {
		t.Fatal("malformed/undated hardening fact accepted")
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
