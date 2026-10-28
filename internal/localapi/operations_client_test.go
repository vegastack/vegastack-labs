package localapi

import (
	"bytes"
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"net/http"
	"strings"
	"testing"
)

func TestOperationsClientUsesFixedRoutesAndRejectsStaleEnvelope(t *testing.T) {
	for _, observe := range []bool{false, true} {
		id, path, method := "api.v1.operations.status", "/api/v1/operations", "GET"
		if observe {
			id = "api.v1.operations.observe"
			path += "/observe"
			method = "POST"
		}
		data := generated.OperationsStatusData{Schema: generated.SchemaIDOperationsStatusData, SchemaVersion: "1.0.0", Alerts: []generated.OperationsAlert{}, Deliveries: []generated.OutboxRecordData{}, StateRevision: 7, RecoveryEpoch: 2, Notifications: "disabled"}
		raw, p, captured := serveFixedResponse(t, http.StatusOK, operationEnvelope(t, id, false, 2, 7, data))
		r, e := NewClient(clientTestFactory()).OperationsStatus(context.Background(), p, observe)
		request := <-captured
		if e != nil || !bytes.Equal(raw, r.Raw) || request.path != path || request.method != method {
			t.Fatal(request, e)
		}
		if observe && (!bytes.Contains(request.body, []byte(`"schema":"vegastack-labs.dev/operations-observe-request"`)) || bytes.Contains(request.body, []byte(`"state"`))) {
			t.Fatal("invalid observation request", string(request.body))
		}
		bad := []byte(strings.Replace(string(raw), `"stateRevision":7`, `"stateRevision":8`, 1))
		_, p, captured = serveFixedResponse(t, http.StatusOK, bad)
		if _, e = NewClient(clientTestFactory()).OperationsStatus(context.Background(), p, observe); e == nil {
			t.Fatal("mismatched envelope accepted")
		}
		<-captured
	}
}
