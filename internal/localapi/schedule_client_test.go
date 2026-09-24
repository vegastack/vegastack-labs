package localapi

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
)

func TestDispatchScheduleUsesServerOwnedTargetDigest(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	policy := generated.BrowserScheduledJobPolicy{Schema: generated.SchemaIDBrowserScheduledJobPolicy, SchemaVersion: "1.0.0", PolicyID: "policy-a", Revision: 3, ActionKind: "backup-create", Enabled: true, Status: "active", ReasonCode: "active", TargetDigest: digest, StateRevision: 7, RecoveryEpoch: 2}
	job := generated.ScheduledJob{Schema: generated.SchemaIDScheduledJob, SchemaVersion: "1.1.0", JobID: "job-a", PolicyID: "policy-a", PolicyRevision: 3, ScheduledAt: "2026-09-24T00:00:00Z", Attempt: 1, Status: "queued", ReasonCode: "due", RecoveryEpoch: 2}
	profile, captured := serveResponseSequence(t, [][]byte{
		operationEnvelope(t, "api.v1.scheduled-job-policies.get", false, 2, 7, policy),
		operationEnvelope(t, "api.v1.scheduled-occurrences.create", true, 2, 8, job),
	})

	response, err := NewClient(clientTestFactory()).DispatchSchedule(context.Background(), profile, "policy-a")
	if err != nil || response.Data.JobID != "job-a" {
		t.Fatalf("dispatch response=%#v err=%v", response, err)
	}
	getRequest, postRequest := <-captured, <-captured
	if getRequest.method != http.MethodGet || getRequest.path != "/api/v1/scheduled-job-policies/policy-a" {
		t.Fatalf("policy request=%#v", getRequest)
	}
	if postRequest.method != http.MethodPost || postRequest.path != "/api/v1/scheduled-job-policies/policy-a/occurrences" {
		t.Fatalf("dispatch request=%#v", postRequest)
	}
	var input generated.ScheduledJobRequest
	if err := json.Unmarshal(postRequest.body, &input); err != nil || input.TargetDigest != digest || input.PolicyRevision != policy.Revision || input.ExpectedStateRevision != policy.StateRevision || input.RecoveryEpoch != policy.RecoveryEpoch {
		t.Fatalf("dispatch body=%s err=%v", postRequest.body, err)
	}
}

func serveResponseSequence(t *testing.T, responses [][]byte) (serverconfig.Profile, <-chan capturedRequest) {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", "vsk-client-sequence-")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "control.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	captured := make(chan capturedRequest, len(responses))
	index := 0
	server := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		captured <- capturedRequest{method: request.Method, path: request.URL.Path, contentType: request.Header.Get("Content-Type"), body: body}
		if index >= len(responses) {
			http.Error(writer, "unexpected request", http.StatusInternalServerError)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write(responses[index])
		index++
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close(); _ = listener.Close(); _ = os.RemoveAll(directory) })
	return serverconfig.Profile{SocketPath: path}, captured
}
