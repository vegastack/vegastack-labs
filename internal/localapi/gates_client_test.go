package localapi

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
)

func TestGateCheckUsesResourceAddressedGeneratedRoute(t *testing.T) {
	definition := generated.GeneratedGateDefinitions[0]
	initial := gateEvaluationFixture(definition, "scope")
	view := generated.GateView{Schema: generated.SchemaIDGateView, SchemaVersion: "1.1.0", Definition: definition, Evaluation: initial, ApplicabilityReasonCode: "subject-binding-unavailable"}
	checked := gateEvaluationFixture(definition, "site-a")
	profile, captured := serveGateCheckResponses(t, definition.GateID, operationEnvelope(t, "api.v1.gates.get", false, 2, 7, view), operationEnvelope(t, "api.v1.gates.check", false, 2, 7, checked))

	response, err := NewClient(clientTestFactory()).CheckGate(context.Background(), profile, definition.GateID, "site-a")
	getRequest, checkRequest := <-captured, <-captured
	if err != nil || response.Data.SubjectID != "site-a" || getRequest.method != http.MethodGet || getRequest.path != "/api/v1/gates/"+definition.GateID || checkRequest.method != http.MethodPost || checkRequest.path != "/api/v1/gates/"+definition.GateID+"/check" || !bytes.Contains(checkRequest.body, []byte(`"gateId":"`+definition.GateID+`"`)) {
		t.Fatalf("gate response/requests = %#v/%#v/%#v err=%v", response, getRequest, checkRequest, err)
	}
}

func gateEvaluationFixture(definition generated.GateDefinition, subject string) generated.GateEvaluation {
	return generated.GateEvaluation{Schema: generated.SchemaIDGateEvaluation, SchemaVersion: "1.1.0", EvaluationID: "eval-a", GateID: definition.GateID, SubjectID: subject, DefinitionVersion: definition.DefinitionVersion, EvaluatorVersion: definition.EvaluatorVersion, EvidenceIDs: []string{}, EvaluatedAt: "2026-09-24T06:00:00Z", RecoveryEpoch: 2, Outcome: "unknown", ReasonCode: "subject-binding-unavailable", EvidenceSource: "none", ReadyForInput: false}
}

func serveGateCheckResponses(t *testing.T, gateID string, getResponse, checkResponse []byte) (serverconfig.Profile, <-chan capturedRequest) {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", "vsk-gate-client-")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "control.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	captured := make(chan capturedRequest, 2)
	server := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		captured <- capturedRequest{method: request.Method, path: request.URL.Path, contentType: request.Header.Get("Content-Type"), body: body}
		writer.Header().Set("Content-Type", "application/json")
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/api/v1/gates/"+gateID:
			_, _ = writer.Write(getResponse)
		case request.Method == http.MethodPost && request.URL.Path == "/api/v1/gates/"+gateID+"/check":
			_, _ = writer.Write(checkResponse)
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close(); _ = listener.Close(); _ = os.RemoveAll(directory) })
	return serverconfig.Profile{SocketPath: path}, captured
}
