package inventory

import (
	"context"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestNormalizeAndValidateReturnsCompleteStableBlockedDraft(t *testing.T) {
	t.Parallel()
	candidate := conflictCandidateFixture()
	adapterFinding := Finding{Code: "UNSUPPORTED_VALUE", Severity: "error", Blocking: true, RecordKind: "asset", RecordID: "asset-a", FieldPath: "lifecycle", Location: "records/asset-a/lifecycle"}
	first, err := NormalizeAndValidate(context.Background(), DecodedCandidate{Candidate: candidate, Findings: []Finding{adapterFinding}})
	if err != nil {
		t.Fatal(err)
	}
	second, err := NormalizeAndValidate(context.Background(), DecodedCandidate{Candidate: reverseCandidate(candidate), Findings: []Finding{adapterFinding}})
	if err != nil {
		t.Fatal(err)
	}
	if first.ValidationStatus != DraftBlocked || second.ValidationStatus != DraftBlocked {
		t.Fatalf("statuses = (%q, %q)", first.ValidationStatus, second.ValidationStatus)
	}
	if first.ContentDigest != second.ContentDigest || !reflect.DeepEqual(first.Findings, second.Findings) {
		t.Fatalf("normalization is order-dependent:\n%#v\n%#v", first, second)
	}
	got := findingCodes(first.Findings)
	for _, code := range []string{"DUPLICATE_IDENTITY", "DUPLICATE_ALIAS", "DUPLICATE_ADDRESS", "MISSING_REFERENCE", "REFERENCE_CYCLE", "UNSUPPORTED_VALUE", "INVALID_CAPACITY"} {
		if !slices.Contains(got, code) {
			t.Errorf("missing finding %s in %v", code, got)
		}
	}
	if len(first.Candidate.Assets) != len(candidate.Assets) || len(first.Candidate.Nodes) != len(candidate.Nodes) {
		t.Fatal("blocked candidate was reduced to a valid subset")
	}
}

func TestNormalizeCanonicalizesIdentityAliasesAddressesAndTimes(t *testing.T) {
	t.Parallel()
	candidate := minimalCandidate()
	candidate.Assets[0].Identities[0].Value = " public-001 "
	candidate.Aliases[0].Value = "EXAMPLE-NODE"
	candidate.Addresses[0].Value = "2001:0db8::1"
	candidate.Source.CapturedAt = time.Date(2026, 9, 8, 17, 30, 0, 0, time.FixedZone("offset", 19800))
	result, err := NormalizeAndValidate(context.Background(), DecodedCandidate{Candidate: candidate})
	if err != nil {
		t.Fatal(err)
	}
	if result.ValidationStatus != DraftValid || result.Candidate.Assets[0].Identities[0].Value != "PUBLIC-001" || result.Candidate.Aliases[0].Value != "example-node" || result.Candidate.Addresses[0].Value != "2001:db8::1" || result.Candidate.Source.CapturedAt.Location() != time.UTC {
		t.Fatalf("canonical candidate = %#v", result.Candidate)
	}
}

func minimalCandidate() DraftCandidate {
	value := int64(8 << 30)
	return DraftCandidate{
		Source:       SourceDescriptor{Kind: "operator-file", AdapterKind: "strict-json", AdapterVersion: "1.0.0", SourceRevision: "public-1", Digest: "sha256:" + strings.Repeat("0", 64), CapturedAt: time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)},
		Assets:       []DraftAsset{{ID: "asset-a", Kind: AssetPhysical, Lifecycle: LifecycleCandidate, Identities: []DraftIdentity{{Kind: "hardware-serial", Value: "PUBLIC-001"}}, HardwareFacts: []DraftHardwareFact{{ID: "memory", Kind: "memory-capacity", IntegerValue: &value, Unit: "bytes"}}}},
		Nodes:        []DraftNode{{ID: "node-a", AssetID: "asset-a"}},
		Aliases:      []DraftAlias{{ID: "alias-a", TargetID: "node-a", Value: "example-node"}},
		Addresses:    []DraftAddress{{ID: "address-a", NodeID: "node-a", Value: "192.0.2.1"}},
		Observations: []DraftObservation{{ID: "observation-a", SubjectID: "asset-a", Kind: "link-state", Value: "up", ObservedAt: time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)}},
		Provenance:   []FieldProvenance{{RecordKind: "asset", RecordID: "asset-a", FieldPath: "identities[0]", Locator: "records/1/identity", CapturedAt: time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC), AdapterVersion: "1.0.0", ValueStatus: "observed"}},
	}
}

func conflictCandidateFixture() DraftCandidate {
	candidate := minimalCandidate()
	invalid := int64(5)
	candidate.Assets = append(candidate.Assets, DraftAsset{ID: "asset-b", Kind: AssetPhysical, Lifecycle: AssetLifecycle("unexpected"), Identities: []DraftIdentity{{Kind: "hardware-serial", Value: "PUBLIC-001"}}, HardwareFacts: []DraftHardwareFact{{ID: "memory-b", Kind: "memory-capacity", IntegerValue: &invalid, Unit: "count"}}})
	candidate.Nodes = append(candidate.Nodes, DraftNode{ID: "node-b", AssetID: "missing", ParentID: "node-c"}, DraftNode{ID: "node-c", AssetID: "asset-b", ParentID: "node-b"})
	candidate.Aliases = append(candidate.Aliases, DraftAlias{ID: "alias-b", TargetID: "node-b", Value: "EXAMPLE-NODE"})
	candidate.Addresses = append(candidate.Addresses, DraftAddress{ID: "address-b", NodeID: "node-b", Value: "192.0.2.1"})
	return candidate
}

func reverseCandidate(candidate DraftCandidate) DraftCandidate {
	candidate.Assets = slices.Clone(candidate.Assets)
	slices.Reverse(candidate.Assets)
	candidate.Nodes = slices.Clone(candidate.Nodes)
	slices.Reverse(candidate.Nodes)
	candidate.Aliases = slices.Clone(candidate.Aliases)
	slices.Reverse(candidate.Aliases)
	candidate.Addresses = slices.Clone(candidate.Addresses)
	slices.Reverse(candidate.Addresses)
	candidate.Observations = slices.Clone(candidate.Observations)
	slices.Reverse(candidate.Observations)
	candidate.Provenance = slices.Clone(candidate.Provenance)
	slices.Reverse(candidate.Provenance)
	return candidate
}

func findingCodes(findings []Finding) []string {
	result := make([]string, 0, len(findings))
	for _, finding := range findings {
		result = append(result, finding.Code)
	}
	return result
}
