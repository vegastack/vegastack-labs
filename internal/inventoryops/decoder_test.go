package inventoryops

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

func TestDecoderRegistryAcceptsOnlyRegisteredFormatsAndExplicitProvenance(t *testing.T) {
	registry := NewDecoderRegistry()
	input := generated.InventoryDraftInput{
		Schema: generated.SchemaIDInventoryDraftInput, SchemaVersion: "1.0.0",
		Source: generated.InventoryDraftSource{Kind: "fixture", AdapterKind: "typed-json", AdapterVersion: "1.0.0", SourceRevision: "source-2", CapturedAt: "2026-09-08T06:00:00Z"},
		Assets: []generated.InventoryDraftAsset{}, Nodes: []generated.InventoryDraftNode{}, Aliases: []generated.InventoryDraftAlias{}, Addresses: []generated.InventoryDraftAddress{}, Observations: []generated.InventoryDraftObservation{}, Provenance: []generated.InventoryFieldProvenance{},
	}
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	captured := time.Date(2026, 9, 8, 6, 0, 0, 0, time.UTC)
	decoded, err := registry.Decode(context.Background(), DecoderRequest{Format: "typed-json", SourceRevision: "source-2", CapturedAt: captured, Content: raw})
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Candidate.Source.SourceRevision != "source-2" || !decoded.Candidate.Source.CapturedAt.Equal(captured) {
		t.Fatalf("provenance = %#v", decoded.Candidate.Source)
	}
	if _, err := registry.Decode(context.Background(), DecoderRequest{Format: "unknown", SourceRevision: "s", CapturedAt: captured, Content: raw}); err == nil {
		t.Fatal("unknown format accepted")
	}
	if _, err := registry.Decode(context.Background(), DecoderRequest{Format: "typed-json", SourceRevision: "rewritten", CapturedAt: captured, Content: raw}); err == nil {
		t.Fatal("mismatched explicit provenance accepted")
	}
}
