package networkingress

import (
	"testing"
	"time"
)

func TestReceiptAloneCannotCompleteRotation(t *testing.T) {
	for _, s := range []RotationState{{}, {ProviderAcknowledged: true, DeclaredConnectorIDs: []string{"connector-a"}, MaterialVersion: "generation-a"}} {
		if got := EvaluateRotation(s, RotationObservation{Complete: true}); got.Stage == "complete" {
			t.Fatal("receipt invented installed generation proof")
		}
	}
}
func TestOldOrMissingConnectorRemainsPartial(t *testing.T) {
	old := Connection{ConnectorID: "connector-a", ConnectionID: "old", OpenedAt: time.Unix(1, 0)}
	s := RotationState{ProviderAcknowledged: true, DeclaredConnectorIDs: []string{"connector-a", "connector-b"}, OldConnections: []Connection{old}, MaterialVersion: "one"}
	if got := EvaluateRotation(s, RotationObservation{Complete: true, Connections: []Connection{old}}); got.Stage != "connector-update-required" {
		t.Fatal(got)
	}
	if got := EvaluateRotation(s, RotationObservation{Complete: true}); got.Stage != "partial" {
		t.Fatal(got)
	}
	if got := EvaluateRotation(s, RotationObservation{Complete: true, Connections: []Connection{{ConnectorID: "connector-a", ConnectionID: "new-a"}, {ConnectorID: "connector-b", ConnectionID: "new-b"}}}); got.Stage != "verification-pending" {
		t.Fatal(got)
	}
}
