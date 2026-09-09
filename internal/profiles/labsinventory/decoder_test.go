package labsinventory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

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
		{SourceRevision: "revision", CapturedAt: time.Now()},
		{SourceRevision: strings.Repeat("r", 129), CapturedAt: time.Date(2026, 9, 9, 7, 30, 0, 0, time.UTC)},
	}
	for _, config := range cases {
		if _, err := NewDecoder(config); err == nil {
			t.Fatalf("NewDecoder(%#v) succeeded", config)
		}
	}
}
