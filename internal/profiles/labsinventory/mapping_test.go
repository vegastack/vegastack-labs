package labsinventory

import (
	"context"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/inventory"
)

func decodeFixture(t *testing.T, path string) inventory.DecodedCandidate {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	decoded, err := newTestDecoder(t).Decode(context.Background(), file)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func proposedAliases(candidate inventory.DraftCandidate) []string {
	var aliases []string
	for _, alias := range candidate.Aliases {
		if len(alias.ID) >= len("-proposed-alias") && string(alias.ID[len(alias.ID)-len("-proposed-alias"):]) == "-proposed-alias" {
			aliases = append(aliases, alias.Value)
		}
	}
	return aliases
}

func assertBlockingFinding(t *testing.T, findings []inventory.Finding, code, fieldPath string) {
	t.Helper()
	for _, finding := range findings {
		if finding.Code == code && finding.FieldPath == fieldPath && finding.Blocking && finding.Severity == "error" {
			return
		}
	}
	t.Fatalf("missing blocking finding %s at %s: %#v", code, fieldPath, findings)
}

func findingRecordIDs(findings []inventory.Finding, code string) []inventory.LocalID {
	var ids []inventory.LocalID
	for _, finding := range findings {
		if finding.Code == code {
			ids = append(ids, finding.RecordID)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

func TestMapLifecycleAndActiveOrdinalsWithoutUsingHostnameAsIdentity(t *testing.T) {
	decoded := decodeFixture(t, "testdata/lifecycle.csv")
	got := decoded.Candidate
	if len(got.Assets) != 5 || len(got.Nodes) != 2 {
		t.Fatalf("assets/nodes = %d/%d", len(got.Assets), len(got.Nodes))
	}
	if aliases := proposedAliases(got); !reflect.DeepEqual(aliases, []string{"vsk-node-01", "vsk-node-02"}) {
		t.Fatalf("proposed aliases = %#v", aliases)
	}
	for _, asset := range got.Assets {
		for _, identity := range asset.Identities {
			if identity.Kind != "hardware-serial" {
				t.Fatalf("invented identity = %#v", identity)
			}
		}
	}
	assertBlockingFinding(t, decoded.Findings, "MISSING_REQUIRED_FIELD", "assets.sheet1-row-000005.lifecycle")
	assertBlockingFinding(t, decoded.Findings, "UNSUPPORTED_VALUE", "assets.sheet1-row-000006.lifecycle")
	assertBlockingFinding(t, decoded.Findings, "MISSING_REQUIRED_FIELD", "assets.sheet1-row-000003.identities.hardware-serial")
}

func TestKnownReportedHostnameConflictBlocksOnlyAffectedAliases(t *testing.T) {
	decoded := decodeFixture(t, "testdata/hostname-conflict.csv")
	normalized, err := inventory.NormalizeAndValidate(context.Background(), decoded)
	if err != nil {
		t.Fatal(err)
	}
	if normalized.ValidationStatus != inventory.DraftBlocked {
		t.Fatalf("status = %q", normalized.ValidationStatus)
	}
	affected := findingRecordIDs(normalized.Findings, "DUPLICATE_ALIAS")
	want := []inventory.LocalID{"sheet1-row-000002-proposed-alias", "sheet1-row-000003-reported-alias"}
	if !reflect.DeepEqual(affected, want) {
		t.Fatalf("affected aliases = %#v", affected)
	}
	if len(normalized.Candidate.Assets) != 3 {
		t.Fatal("blocked candidate lost unaffected assets")
	}
}

func TestMatchingReportedAndProposedAliasCoalescesWithTwoSources(t *testing.T) {
	decoded := decodeFixture(t, "testdata/lifecycle.csv")
	aliasID := inventory.LocalID("sheet1-row-000002-proposed-alias")
	count := 0
	for _, alias := range decoded.Candidate.Aliases {
		if alias.ID == aliasID {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("matching alias records = %d", count)
	}
	provenance := 0
	for _, source := range decoded.Candidate.Provenance {
		if source.RecordID == aliasID {
			provenance++
		}
	}
	if provenance != 2 {
		t.Fatalf("matching alias provenance = %d", provenance)
	}
}

func TestMapRecordsHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := mapRecords(ctx, newTestDecoder(t).config, [][]string{make([]string, len(headerV1))})
	assertDecodeCode(t, err, ErrorInterrupted)
}

func TestDuplicateSerialsStayCompleteAndBlockedByCore(t *testing.T) {
	raw := strings.Join(expectedHeaderV1, ",") + "\n" +
		"active,SYNTHETIC-DUPLICATE,,ExampleCorp,ExampleModel,amd64,ExampleCPU,4,8,8,256,0,16,512,0\n" +
		"active,SYNTHETIC-DUPLICATE,,ExampleCorp,ExampleModel,amd64,ExampleCPU,4,8,8,256,0,16,512,0\n"
	decoded, err := newTestDecoder(t).Decode(context.Background(), strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	normalized, err := inventory.NormalizeAndValidate(context.Background(), decoded)
	if err != nil {
		t.Fatal(err)
	}
	if normalized.ValidationStatus != inventory.DraftBlocked || len(normalized.Candidate.Assets) != 2 || len(findingRecordIDs(normalized.Findings, "DUPLICATE_IDENTITY")) != 2 {
		t.Fatalf("duplicate serial result = %#v", normalized)
	}
}
