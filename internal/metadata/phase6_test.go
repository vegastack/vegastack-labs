package metadata

import "testing"

// Phase 6 adds provider-neutral host identity, role, role-alias, OS-profile and
// host-hardening evidence contracts, plus host hardening/role-admission gate
// definitions. These are inert public shapes; they assert no admission.

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

func phase6Contains(values []string, target string) bool {
	for _, v := range values {
		if v == target {
			return true
		}
	}
	return false
}
