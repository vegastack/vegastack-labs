package labsinventory

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
)

func csvWithUnknownHeader(header string) string {
	fields := append([]string(nil), expectedHeaderV1...)
	fields[4] = header
	return strings.Join(fields, ",") + "\n"
}

func csvWithExtraCell(cell string) string {
	return strings.Join(expectedHeaderV1, ",") + "\n" + strings.Repeat(",", len(expectedHeaderV1)-1) + "," + cell + "\n"
}

func readRepoFile(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestRejectedPrivateCanariesNeverEscape(t *testing.T) {
	decoder := newTestDecoder(t)
	canary := strings.Join([]string{"github", "_pat_", "public-test-canary"}, "")
	inputs := []string{csvWithUnknownHeader(canary), csvWithModel(canary), csvWithExtraCell(canary)}
	for _, input := range inputs {
		decoded, err := decoder.Decode(context.Background(), strings.NewReader(input))
		encoded, marshalErr := json.Marshal(decoded)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		exposed := fmt.Sprintf("%s|%v", encoded, err)
		if strings.Contains(exposed, canary) {
			t.Fatalf("canary escaped: %s", exposed)
		}
	}
}

func TestPublishedTemplatesMatchContractAndContainOnlySyntheticRows(t *testing.T) {
	headerOnly := readRepoFile(t, "../../../docs/examples/labs-sheet1-import-v1-header.csv")
	if string(headerOnly) != strings.Join(expectedHeaderV1, ",")+"\n" {
		t.Fatal("header template drift")
	}
	example := readRepoFile(t, "../../../docs/examples/labs-sheet1-import-v1-example.csv")
	decoded, err := newTestDecoder(t).Decode(context.Background(), bytes.NewReader(example))
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded.Candidate.Assets) == 0 || !bytes.Contains(example, []byte("SYNTHETIC-")) {
		t.Fatal("example is not a populated synthetic fixture")
	}
	forbidden := regexp.MustCompile(`(?i)(PF[0-9A-Z]{6}|PG[0-9A-Z]{6}|labs\.vegastack\.com|password|token|secret|credential)`)
	if forbidden.Match(example) {
		t.Fatal("example contains private or credential-like material")
	}
}

func TestPackageContainsNoAuthorityOrOnlineCompositionPath(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	forbidden := regexp.MustCompile(`(?m)"(database/sql|net/http|github\.com/vegastack/vegastack-labs/internal/(cli|store|generated|providers?)[^"]*)"`)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		raw := readRepoFile(t, entry.Name())
		if forbidden.Match(raw) {
			t.Fatalf("disallowed dependency in %s", entry.Name())
		}
	}
}
