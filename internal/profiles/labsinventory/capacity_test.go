package labsinventory

import (
	"context"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/inventory"
)

func TestDecimalGBIsExactAndOverflowChecked(t *testing.T) {
	cases := []struct {
		input string
		want  int64
		ok    bool
	}{
		{"", 0, false}, {"0", 0, true}, {"016", 16_000_000_000, true},
		{"512", 512_000_000_000, true}, {"1.5", 0, false}, {"1 TB", 0, false},
		{"9223372037", 0, false}, {"-1", 0, false}, {" 16", 0, false},
	}
	for _, tc := range cases {
		got, ok := parseDecimalGB(tc.input)
		if got != tc.want || ok != tc.ok {
			t.Errorf("parseDecimalGB(%q) = (%d,%v)", tc.input, got, ok)
		}
	}
}

func factsForAsset(candidate inventory.DraftCandidate, id inventory.LocalID) []inventory.DraftHardwareFact {
	for _, asset := range candidate.Assets {
		if asset.ID == id {
			return asset.HardwareFacts
		}
	}
	return nil
}

func factByID(facts []inventory.DraftHardwareFact, id inventory.LocalID) (inventory.DraftHardwareFact, bool) {
	for _, fact := range facts {
		if fact.ID == id {
			return fact, true
		}
	}
	return inventory.DraftHardwareFact{}, false
}

func assertIntegerFact(t *testing.T, facts []inventory.DraftHardwareFact, id inventory.LocalID, value int64, unit string) {
	t.Helper()
	fact, ok := factByID(facts, id)
	if !ok || fact.IntegerValue == nil || *fact.IntegerValue != value || fact.Unit != unit {
		t.Fatalf("fact %s = %#v", id, fact)
	}
}

func hasFact(facts []inventory.DraftHardwareFact, id inventory.LocalID) bool {
	_, ok := factByID(facts, id)
	return ok
}

func provenanceCount(candidate inventory.DraftCandidate, id inventory.LocalID) int {
	count := 0
	for _, source := range candidate.Provenance {
		if source.RecordKind == "asset" && source.RecordID == id {
			count++
		}
	}
	return count
}

func assertObservation(t *testing.T, candidate inventory.DraftCandidate, id inventory.LocalID, kind, value string) {
	t.Helper()
	for _, observation := range candidate.Observations {
		if observation.ID == id && observation.Kind == kind && observation.Value == value {
			return
		}
	}
	t.Fatalf("missing observation %s (%s/%s)", id, kind, value)
}

func TestCurrentAndFactoryFactsRemainDistinctWithoutInvalidFallback(t *testing.T) {
	decoded := decodeFixture(t, "testdata/capacity-precedence.csv")
	facts := factsForAsset(decoded.Candidate, "sheet1-row-000002-asset")
	assertIntegerFact(t, facts, "sheet1-row-000002-factory-memory", 8_000_000_000, "bytes")
	assertIntegerFact(t, facts, "sheet1-row-000002-current-memory", 16_000_000_000, "bytes")
	assertIntegerFact(t, facts, "sheet1-row-000002-factory-ssd", 256_000_000_000, "bytes")
	assertIntegerFact(t, facts, "sheet1-row-000002-current-ssd", 512_000_000_000, "bytes")
	assertObservation(t, decoded.Candidate, "sheet1-row-000002-factory-observation", "labs-sheet1-factory", "reported")
	assertObservation(t, decoded.Candidate, "sheet1-row-000002-current-observation", "labs-sheet1-current", "preferred")
	assertBlockingFinding(t, decoded.Findings, "INVALID_CAPACITY", "hardwareFacts.sheet1-row-000003-current-memory.integerValue")
	if hasFact(factsForAsset(decoded.Candidate, "sheet1-row-000003-asset"), "sheet1-row-000003-current-memory") {
		t.Fatal("invalid current capacity became a fact or factory fallback")
	}
	if got := provenanceCount(decoded.Candidate, "sheet1-row-000002-asset"); got != 15 {
		t.Fatalf("provenance count = %d", got)
	}
}

func TestCountsAndTextFactsPreserveTypedSourceValues(t *testing.T) {
	decoded := decodeFixture(t, "testdata/capacity-precedence.csv")
	facts := factsForAsset(decoded.Candidate, "sheet1-row-000002-asset")
	assertIntegerFact(t, facts, "sheet1-row-000002-cpu-physical-cores", 4, "count")
	assertIntegerFact(t, facts, "sheet1-row-000002-cpu-logical-threads", 8, "count")
	model, ok := factByID(facts, "sheet1-row-000002-model")
	if !ok || model.TextValue == nil || *model.TextValue != "ExampleModel" {
		t.Fatalf("model fact = %#v", model)
	}
	assertBlockingFinding(t, decoded.Findings, "UNSUPPORTED_VALUE", "hardwareFacts.sheet1-row-000004-cpu-physical-cores.integerValue")
}

func TestAbsentHardwareGroupsDoNotCreateObservations(t *testing.T) {
	raw := strings.Join(expectedHeaderV1, ",") + "\n" +
		"retired,SYNTHETIC-NO-HARDWARE,,,,,,,,,,,,,\n"
	decoded, err := newTestDecoder(t).Decode(context.Background(), strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded.Candidate.Observations) != 0 {
		t.Fatalf("observations = %#v", decoded.Candidate.Observations)
	}
}
