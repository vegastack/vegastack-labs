package metadata

import "testing"

func TestHostDiscoveryContracts(t *testing.T) {
	registry := Current()
	found := map[string]bool{}
	for _, s := range registry.Schemas {
		found[s.ID] = true
	}
	for _, id := range []string{"host-discovery-target-draft-request", "host-discovery-request", "host-observation", "host-discovery-submission"} {
		if !found["vegastack-labs.dev/"+id] {
			t.Errorf("missing discovery contract %s", id)
		}
	}
	if err := Validate(registry); err != nil {
		t.Fatal(err)
	}
}
func TestDiscoveryCannotActivateHostGates(t *testing.T) {
	for _, gate := range CurrentGateDefinitions() {
		if (gate.GateID == "host.hardening-baseline" || gate.GateID == "host.role-admission") && (gate.EvaluatorVersion != "1.1.0" || gate.DefinitionVersion != "1.1.0") {
			t.Fatal("host admission must require the dedicated versioned evaluator")
		}
	}
}
