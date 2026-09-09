package stateexport

import (
	"bytes"
	"os"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/inventory"
)

func publicPayloadFixture(t *testing.T) Payload {
	t.Helper()
	sourceRevision := "0123456789abcdef0123456789abcdef01234567"
	textValue := "synthetic-model"
	return Payload{
		Schema: PayloadSchema, SchemaVersion: SchemaVersion,
		ExportKind: ExportKind, SubjectKind: SubjectKind,
		RecoveryEpoch: 2, StateRevision: 7,
		ToolVersion: "0.0.0-test", ReleaseBuildID: "synthetic-test-only-build", SourceRevision: &sourceRevision,
		Contents: []KindCount{{Kind: "inventory-draft", Count: 1}},
		Draft: inventory.CanonicalDraftSnapshot{
			Kind: "draft", Ref: inventory.DraftRef{ID: "draft-test-1", Revision: 1}, ValidationStatus: inventory.DraftValid,
			Source: inventory.SourceDescriptor{
				Kind: "synthetic", AdapterKind: "fixture", AdapterVersion: "1.0.0", SourceRevision: "fixture-1",
				Digest:     "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				CapturedAt: time.Date(2026, 9, 8, 10, 0, 0, 0, time.UTC),
			},
			Assets: []inventory.DraftAsset{{
				ID: "asset-test-1", Kind: inventory.AssetPhysical, Lifecycle: inventory.LifecycleCandidate,
				Identities:    []inventory.DraftIdentity{{Kind: "hardware-serial", Value: "SYNTHETIC-001", Quarantined: false}},
				HardwareFacts: []inventory.DraftHardwareFact{{ID: "fact-test-1", Kind: "model", TextValue: &textValue, Unit: ""}},
			}},
			Nodes: []inventory.DraftNode{}, Aliases: []inventory.DraftAlias{}, Addresses: []inventory.DraftAddress{},
			Observations: []inventory.DraftObservation{}, Provenance: []inventory.FieldProvenance{}, Findings: []inventory.Finding{},
			ContentDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		},
	}
}

func TestCanonicalPayloadIsByteStableAndExplicitlyInert(t *testing.T) {
	first := publicPayloadFixture(t)
	second := publicPayloadFixture(t)
	got1, digest1, err := CanonicalPayload(first)
	if err != nil {
		t.Fatal(err)
	}
	got2, digest2, err := CanonicalPayload(second)
	if err != nil {
		t.Fatal(err)
	}
	golden, err := os.ReadFile("testdata/payload-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got1, bytes.TrimSuffix(golden, []byte("\n"))) || !bytes.Equal(got1, got2) || digest1 != digest2 {
		t.Fatalf("canonical mismatch: %s / %s", got1, got2)
	}
	if first.ExportKind != ExportKind || first.SubjectKind != SubjectKind || bytes.Contains(got1, []byte(`"declared"`)) || bytes.Contains(got1, []byte(`"effective"`)) {
		t.Fatalf("artifact semantics elevated: %s", got1)
	}
}

func TestSignedExportDecodeRequiresExactCanonicalClosedDocument(t *testing.T) {
	raw, err := os.ReadFile("testdata/signed-export-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	raw = bytes.TrimSuffix(raw, []byte("\n"))
	decoded, err := DecodeSignedExport(raw)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _, err := CanonicalSignedExport(decoded)
	if err != nil || !bytes.Equal(raw, encoded) {
		t.Fatalf("round trip = %q, %v", encoded, err)
	}
	altered := [][]byte{
		append(append([]byte(nil), raw...), '\n'),
		bytes.Replace(raw, []byte(`"schemaVersion":"1.0.0"`), []byte(`"schemaVersion":"1.0.0","unknown":true`), 1),
		bytes.Replace(raw, []byte(`"exportKind":"inventory-draft-snapshot"`), []byte(`"exportKind":"inventory-draft-snapshot","exportKind":"inventory-draft-snapshot"`), 1),
		bytes.Replace(raw, []byte(`"subjectKind":"draft"`), []byte(`"subjectKind":"declaration"`), 1),
	}
	for _, candidate := range altered {
		if _, err := DecodeSignedExport(candidate); err == nil {
			t.Fatalf("noncanonical document accepted: %s", candidate)
		}
	}
}

func TestCanonicalPayloadRejectsNilCollectionsAndWrongDraftSemantics(t *testing.T) {
	for name, mutate := range map[string]func(*Payload){
		"nil contents": func(value *Payload) { value.Contents = nil },
		"nil nested":   func(value *Payload) { value.Draft.Nodes = nil },
		"wrong kind":   func(value *Payload) { value.Draft.Kind = "inventory" },
		"wrong ref":    func(value *Payload) { value.Draft.Ref.Revision = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			value := publicPayloadFixture(t)
			mutate(&value)
			if _, _, err := CanonicalPayload(value); err == nil {
				t.Fatal("invalid payload accepted")
			}
		})
	}
}
