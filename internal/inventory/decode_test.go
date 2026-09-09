package inventory

import (
	"context"
	"errors"
	"io"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

func TestJSONDecoderIsStrictBoundedAndSanitized(t *testing.T) {
	t.Parallel()
	valid, err := os.Open("testdata/minimal.json")
	if err != nil {
		t.Fatal(err)
	}
	defer valid.Close()
	decoded, err := (JSONDecoder{}).Decode(context.Background(), valid)
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(decoded.Candidate.Source.Digest) {
		t.Fatalf("source digest = %q", decoded.Candidate.Source.Digest)
	}
	if len(decoded.Findings) != 0 || len(decoded.Candidate.Assets) != 1 {
		t.Fatalf("decoded candidate = %#v", decoded)
	}

	canary := "github_pat_public-test-canary-value"
	_, err = (JSONDecoder{}).Decode(context.Background(), strings.NewReader(`{"schema":"vegastack-labs.dev/inventory-draft-input","schemaVersion":"1.0.0","unknown":"`+canary+`"}`))
	if err == nil || strings.Contains(err.Error(), canary) {
		t.Fatalf("unknown-field error leaked input: %v", err)
	}
	_, err = (JSONDecoder{}).Decode(context.Background(), io.LimitReader(strings.NewReader(strings.Repeat("x", MaxInputBytes+2)), MaxInputBytes+2))
	if err == nil {
		t.Fatal("oversized input accepted")
	}
}

func TestJSONDecoderRejectsCallerForgedAuthenticatedPrincipal(t *testing.T) {
	t.Parallel()
	raw := strings.TrimSpace(readMinimal(t))
	raw = strings.TrimSuffix(raw, "}") + `,"authenticatedPrincipalId":"principal-admin"}`
	_, err := (JSONDecoder{}).Decode(context.Background(), strings.NewReader(raw))
	assertInventoryCode(t, err, generated.ErrorCodeInputInvalid)
}

func TestJSONDecoderRejectsUnsafeEnvelopesWithoutValues(t *testing.T) {
	t.Parallel()
	valid, err := os.ReadFile("testdata/minimal.json")
	if err != nil {
		t.Fatal(err)
	}
	tests := [][]byte{
		nil,
		append([]byte{0xef, 0xbb, 0xbf}, valid...),
		append(valid, []byte(`{}`)...),
		[]byte(`{"schema":"vegastack-labs.dev/inventory-draft-input","schema":"shadow"}`),
		[]byte{0xff, 0xfe},
		append([]byte(nil), append(valid[:len(valid)-2], 0)...),
	}
	for _, input := range tests {
		_, err := (JSONDecoder{}).Decode(context.Background(), strings.NewReader(string(input)))
		var domainErr *Error
		if !errors.As(err, &domainErr) || domainErr.Code != generated.ErrorCodeInputInvalid {
			t.Fatalf("Decode returned %v", err)
		}
	}
}

func TestJSONDecoderReportsWrongSchemaAndCancellation(t *testing.T) {
	t.Parallel()
	raw := strings.Replace(readMinimal(t), generated.SchemaIDInventoryDraftInput, "example.invalid/other", 1)
	_, err := (JSONDecoder{}).Decode(context.Background(), strings.NewReader(raw))
	assertInventoryCode(t, err, generated.ErrorCodeSchemaUnsupported)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = (JSONDecoder{}).Decode(ctx, strings.NewReader(readMinimal(t)))
	assertInventoryCode(t, err, generated.ErrorCodeInterrupted)
}

func readMinimal(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile("testdata/minimal.json")
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func assertInventoryCode(t *testing.T, err error, code string) *Error {
	t.Helper()
	var domainErr *Error
	if !errors.As(err, &domainErr) || domainErr.Code != code {
		t.Fatalf("error = %v, want inventory code %s", err, code)
	}
	return domainErr
}
