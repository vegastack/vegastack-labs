package labsinventory

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/inventory"
)

type countingReader struct {
	reader *strings.Reader
	read   int
}

func (reader *countingReader) Read(buffer []byte) (int, error) {
	read, err := reader.reader.Read(buffer)
	reader.read += read
	return read, err
}

var expectedHeaderV1 = []string{
	"lifecycle", "hardware_serial", "reported_hostname", "manufacturer", "model",
	"cpu_architecture", "cpu_model", "cpu_physical_cores", "cpu_logical_threads",
	"factory_ram_gb", "factory_ssd_gb", "factory_hdd_gb", "current_ram_gb",
	"current_ssd_gb", "current_hdd_gb",
}

func newTestDecoder(t *testing.T) *Decoder {
	t.Helper()
	decoder, err := NewDecoder(Config{
		SourceRevision: "synthetic-revision-1",
		CapturedAt:     time.Date(2026, 9, 9, 7, 30, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	return decoder
}

func assertDecodeCode(t *testing.T, err error, code string) {
	t.Helper()
	var decodeErr *DecodeError
	if !errors.As(err, &decodeErr) {
		t.Fatalf("error = %T %v, want DecodeError %s", err, err, code)
	}
	if decodeErr.Code != code {
		t.Fatalf("error code = %q, want %q", decodeErr.Code, code)
	}
}

func csvWithModel(model string) string {
	row := []string{"active", "SYNTHETIC-SERIAL-001", "example-node", "ExampleCorp", model, "amd64", "ExampleCPU", "4", "8", "8", "256", "0", "16", "512", "0"}
	return strings.Join(expectedHeaderV1, ",") + "\n" + strings.Join(row, ",") + "\n"
}

func TestDecoderRequiresExactV1HeaderAndHashesOriginalBytes(t *testing.T) {
	decoder := newTestDecoder(t)
	raw := "\ufeff" + strings.Join(expectedHeaderV1, ",") + "\r\n"
	decoded, err := decoder.Decode(context.Background(), strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256([]byte(raw))
	if decoded.Candidate.Source.Digest != "sha256:"+hex.EncodeToString(want[:]) {
		t.Fatalf("digest = %q", decoded.Candidate.Source.Digest)
	}
	reordered := append([]string(nil), expectedHeaderV1...)
	reordered[1], reordered[2] = reordered[2], reordered[1]
	_, err = decoder.Decode(context.Background(), strings.NewReader(strings.Join(reordered, ",")+"\n"))
	assertDecodeCode(t, err, "CSV_HEADER_ORDER")
}

func TestDecoderAcceptsQuotedCSVAndRejectsLimitsFormulaControlsAndCancellation(t *testing.T) {
	decoder := newTestDecoder(t)
	file, err := os.Open("testdata/quoted.csv")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := decoder.Decode(context.Background(), file); err != nil {
		t.Fatal(err)
	}
	cases := []struct{ name, cell, code string }{
		{"formula", "\u2003=2+2", "CSV_FORMULA_PROHIBITED"},
		{"nul", "bad\x00value", "CSV_CONTROL_PROHIBITED"},
		{"bidi", "bad\u202evalue", "CSV_CONTROL_PROHIBITED"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := decoder.Decode(context.Background(), strings.NewReader(csvWithModel(tc.cell)))
			assertDecodeCode(t, err, tc.code)
			if strings.Contains(fmt.Sprint(err), tc.cell) {
				t.Fatal("error echoed rejected cell")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = decoder.Decode(ctx, strings.NewReader(strings.Join(expectedHeaderV1, ",")+"\n"))
	assertDecodeCode(t, err, "INTERRUPTED")
}

func TestNewDecoderRejectsUntrustedSourceMetadata(t *testing.T) {
	cases := []Config{
		{},
		{SourceRevision: "revision", CapturedAt: time.Date(2026, 9, 9, 7, 30, 0, 0, time.FixedZone("non-UTC", 5*60*60+30*60))},
		{SourceRevision: strings.Repeat("r", 129), CapturedAt: time.Date(2026, 9, 9, 7, 30, 0, 0, time.UTC)},
	}
	for _, config := range cases {
		if _, err := NewDecoder(config); err == nil {
			t.Fatalf("NewDecoder(%#v) succeeded", config)
		}
	}
}

func TestDecoderClassifiesHeaderAndCSVFailuresWithoutEcho(t *testing.T) {
	header := strings.Join(expectedHeaderV1, ",")
	duplicate := append([]string(nil), expectedHeaderV1...)
	duplicate[1] = duplicate[0]
	missing := expectedHeaderV1[:len(expectedHeaderV1)-1]
	unknown := append([]string(nil), expectedHeaderV1...)
	unknown[4] = "unexpected_public_column"
	cases := []struct {
		name string
		raw  string
		code string
	}{
		{"duplicate-header", strings.Join(duplicate, ",") + "\n", ErrorCSVHeaderDuplicate},
		{"missing-header", strings.Join(missing, ",") + "\n", ErrorCSVHeaderMissing},
		{"unknown-header", strings.Join(unknown, ",") + "\n", ErrorCSVHeaderUnknown},
		{"malformed-quote", header + "\nactive,\"unterminated\n", ErrorCSVMalformed},
		{"wrong-row-width", header + "\nactive,too-short\n", ErrorCSVMalformed},
		{"invalid-utf8", header + "\n" + string([]byte{0xff}), ErrorCSVUTF8Invalid},
		{"misplaced-bom", header + "\nactive,SYNTHETIC-1,\ufeffbad,,,,,,,,,,,,\n", ErrorCSVControlProhibited},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := newTestDecoder(t).Decode(context.Background(), strings.NewReader(tc.raw))
			assertDecodeCode(t, err, tc.code)
			if strings.Contains(fmt.Sprint(err), "unexpected_public_column") || strings.Contains(fmt.Sprint(err), "unterminated") {
				t.Fatal("error echoed rejected source")
			}
		})
	}
}

func TestDecoderAcceptsLineEndingsAndRejectsEveryProhibitedCellClass(t *testing.T) {
	for _, raw := range []string{
		strings.Join(expectedHeaderV1, ",") + "\n",
		strings.Join(expectedHeaderV1, ",") + "\r\n",
		"\ufeff" + strings.Join(expectedHeaderV1, ",") + "\n",
	} {
		if _, err := newTestDecoder(t).Decode(context.Background(), strings.NewReader(raw)); err != nil {
			t.Fatal(err)
		}
	}
	for _, cell := range []string{"=1", "+1", "-1", "@value", "\u00a0=1"} {
		_, err := newTestDecoder(t).Decode(context.Background(), strings.NewReader(csvWithModel(cell)))
		assertDecodeCode(t, err, ErrorCSVFormulaProhibited)
	}
	for _, cell := range []string{"bad\tvalue", "bad\x7fvalue", "bad\u0085value", "bad\u202dvalue", "bad\u2067value", "bad\ufdd0value", "bad\ufffevalue"} {
		_, err := newTestDecoder(t).Decode(context.Background(), strings.NewReader(csvWithModel(cell)))
		assertDecodeCode(t, err, ErrorCSVControlProhibited)
	}
}

func TestDecoderEnforcesExactReadRecordAndFieldLimits(t *testing.T) {
	tooLarge := &countingReader{reader: strings.NewReader(strings.Repeat("x", MaxInputBytes+100))}
	_, err := newTestDecoder(t).Decode(context.Background(), tooLarge)
	assertDecodeCode(t, err, ErrorCSVLimitExceeded)
	if tooLarge.read != MaxInputBytes+1 {
		t.Fatalf("bytes read = %d, want %d", tooLarge.read, MaxInputBytes+1)
	}

	longModel := strings.Repeat("x", MaxFieldBytes+1)
	_, err = newTestDecoder(t).Decode(context.Background(), strings.NewReader(csvWithModel(longModel)))
	assertDecodeCode(t, err, ErrorCSVLimitExceeded)

	var many bytes.Buffer
	many.WriteString(strings.Join(expectedHeaderV1, ",") + "\n")
	for index := 1; index < MaxCSVRecords; index++ {
		many.WriteString("active,SYNTHETIC-ROW,,,,,,,,,,,,,\n")
	}
	many.WriteString("active,SYNTHETIC-OVER,,,,,,,,,,,,,\n")
	_, err = newTestDecoder(t).Decode(context.Background(), bytes.NewReader(many.Bytes()))
	assertDecodeCode(t, err, ErrorCSVLimitExceeded)
}

func TestDecoderRejectsExpandedCandidateBeyondCoreLimits(t *testing.T) {
	var provenanceHeavy bytes.Buffer
	provenanceHeavy.WriteString(strings.Join(expectedHeaderV1, ",") + "\n")
	for index := 0; index < inventory.MaxProvenance/len(headerV1)+1; index++ {
		provenanceHeavy.WriteString(fmt.Sprintf("retired,SYNTHETIC-LIMIT-%06d,,,,,,,,,,,,,\n", index))
	}
	_, err := newTestDecoder(t).Decode(context.Background(), bytes.NewReader(provenanceHeavy.Bytes()))
	assertDecodeCode(t, err, ErrorCSVLimitExceeded)

	var primaryHeavy bytes.Buffer
	primaryHeavy.WriteString(strings.Join(expectedHeaderV1, ",") + "\n")
	for index := 0; index < inventory.MaxPrimaryRecords/3+1; index++ {
		primaryHeavy.WriteString(fmt.Sprintf("active,SYNTHETIC-ACTIVE-%06d,,,,,,,,,,,,,\n", index))
	}
	_, err = newTestDecoder(t).Decode(context.Background(), bytes.NewReader(primaryHeavy.Bytes()))
	assertDecodeCode(t, err, ErrorCSVLimitExceeded)
}
