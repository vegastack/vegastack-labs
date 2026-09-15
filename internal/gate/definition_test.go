package gate

import (
	"encoding/json"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

func TestLabsGateIsNotUniversal(t *testing.T) {
	minimal := ResolvedScope{ProfileID: "minimal-no-account", ProfileVersion: "1.0.0", PolicyID: "policy-a", PolicyVersion: "1.0.0"}
	labs := ResolvedScope{ProfileID: "vegastack-labs", ProfileVersion: "1.0.0", PolicyID: "policy-a", PolicyVersion: "1.0.0"}
	if HasApplicable(ResolveDefinitions(minimal, "site"), "G-008") {
		t.Fatal("Labs gate became core")
	}
	if !HasApplicable(ResolveDefinitions(labs, "site"), "G-008") {
		t.Fatal("Labs gate missing")
	}
	if !HasApplicable(ResolveDefinitions(minimal, "site"), "platform-safety") {
		t.Fatal("core safety bypassed")
	}
}

func TestMissingAppliedScopeDoesNotSynthesizeProfile(t *testing.T) {
	if got := ResolveDefinitions(ResolvedScope{}, "site"); len(got) != 0 {
		t.Fatalf("missing applied binding synthesized %d definitions", len(got))
	}
}

func TestGeneratedGateDefinitionsValidateAndDeferOutOfScopeWork(t *testing.T) {
	if len(generated.GeneratedGateDefinitions) != 24 { t.Fatalf("definitions = %d", len(generated.GeneratedGateDefinitions)) }
	for _, definition := range generated.GeneratedGateDefinitions {
		raw, err := json.Marshal(definition)
		if err != nil { t.Fatal(err) }
		if err := generated.ValidateContractJSON(generated.SchemaIDGateDefinition, raw, generated.ContractExact); err != nil {
			t.Fatalf("%s: %v", definition.GateID, err)
		}
	}
	labs := ResolvedScope{ProfileID: "vegastack-labs", ProfileVersion: "1.0.0", PolicyID: "policy-a", PolicyVersion: "1.0.0"}
	if HasApplicable(ResolveDefinitions(labs, "service"), "G-023") { t.Fatal("deferred Chaabi Prod became v1 gate") }
	if HasApplicable(ResolveDefinitions(labs, "service"), "G-022") { t.Fatal("conditional service gate enabled without capability") }
	labs.Capabilities = []string{"service-admission"}
	if !HasApplicable(ResolveDefinitions(labs, "service"), "G-022") { t.Fatal("enabled service gate missing") }
}
