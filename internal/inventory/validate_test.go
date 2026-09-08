package inventory

import (
	"context"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

func TestNormalizeRejectsInvalidAdapterFindingAndLimits(t *testing.T) {
	t.Parallel()
	_, err := NormalizeAndValidate(context.Background(), DecodedCandidate{Candidate: minimalCandidate(), Findings: []Finding{{Code: "NOT_REGISTERED", Severity: "error", Blocking: true}}})
	assertInventoryCode(t, err, generated.ErrorCodeInputInvalid)

	over := minimalCandidate()
	over.Assets = make([]DraftAsset, MaxPrimaryRecords+1)
	_, err = NormalizeAndValidate(context.Background(), DecodedCandidate{Candidate: over})
	assertInventoryCode(t, err, generated.ErrorCodeInputInvalid)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = NormalizeAndValidate(ctx, DecodedCandidate{Candidate: minimalCandidate()})
	assertInventoryCode(t, err, generated.ErrorCodeInterrupted)
}

func TestNormalizeEnforcesTokenLocatorAndTextBounds(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		change func(*DraftCandidate)
	}{
		{name: "token", change: func(candidate *DraftCandidate) {
			candidate.Assets[0].ID = LocalID(strings.Repeat("a", MaxTokenBytes+1))
		}},
		{name: "locator", change: func(candidate *DraftCandidate) {
			candidate.Provenance[0].Locator = strings.Repeat("l", MaxLocatorBytes+1)
		}},
		{name: "text", change: func(candidate *DraftCandidate) { candidate.Observations[0].Value = strings.Repeat("v", MaxTextBytes+1) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := minimalCandidate()
			test.change(&candidate)
			_, err := NormalizeAndValidate(context.Background(), DecodedCandidate{Candidate: candidate})
			assertInventoryCode(t, err, generated.ErrorCodeInputInvalid)
		})
	}
}

func TestNormalizeDeduplicatesExactAdapterFindings(t *testing.T) {
	t.Parallel()
	finding := Finding{Code: "UNSUPPORTED_VALUE", Severity: "error", Blocking: true, RecordKind: "asset", RecordID: "asset-a", FieldPath: "lifecycle", Location: "records/asset-a/lifecycle"}
	result, err := NormalizeAndValidate(context.Background(), DecodedCandidate{Candidate: minimalCandidate(), Findings: []Finding{finding, finding}})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 1 || result.ValidationStatus != DraftBlocked {
		t.Fatalf("result = %#v", result)
	}
}
