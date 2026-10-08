package api

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDiscoveryInputKeepsLegacyOptionalConfirmation(t *testing.T) {
	for _, suffix := range []string{"", `,"consoleConfirmation":null`} {
		raw := `{"schema":"vegastack-labs.dev/host-discovery-target-draft-request","schemaVersion":"1.0.0","target":{"schema":"vegastack-labs.dev/host-discovery-target","schemaVersion":"1.0.0","targetId":"fixture","revision":1,"address":"127.0.0.1","port":2222,"user":"inspect","hostKey":"public-fixture","profileId":"profile","credentialReferenceId":"key","materialVersion":"v1","expectedOs":"debian","expectedVersion":"13","expectedArchitecture":"amd64","inventoryDraftId":null,"inventoryDraftRevision":0,"assetId":null,"recoveryEpoch":0},"action":"activate","expectedTargetRevision":0,"expectedStateRevision":0,"idempotencyKey":"fixture"` + suffix + `}`
		r := httptest.NewRequest("POST", "/api/v1/host-discovery-targets/draft", strings.NewReader(raw))
		r.Header.Set("Content-Type", "application/json")
		var out generated.HostDiscoveryTargetDraftRequest
		if err := discoveryInput(r, generated.SchemaIDHostDiscoveryTargetDraftRequest, []string{"schema", "schemaVersion", "target", "action", "expectedTargetRevision", "expectedStateRevision", "idempotencyKey"}, &out); err != nil {
			t.Fatal(err)
		}
	}
}
