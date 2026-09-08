package inventory

import (
	"context"
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
