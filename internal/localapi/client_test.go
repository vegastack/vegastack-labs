package localapi

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/result"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
)

func clientTestFactory() *result.Factory {
	return result.NewFactory(result.BuildInfo{ToolVersion: "0.2.0-test", ReleaseBuildID: "build-client"}, func() (string, error) { return "request-local", nil })
}

func clientTestEnvelope(t *testing.T) []byte {
	t.Helper()
	status := generated.ServerStatusData{State: "ready", ReadAvailable: true, MutationAvailable: false, RecoveryEpoch: 7, StateRevision: 42, RemoteReadState: "disabled", RemoteReadReason: "none"}
	factory := clientTestFactory()
	envelope, err := factory.Success(generated.CommandNameServerStatus, 7, 42, status)
	if err != nil {
		t.Fatal(err)
	}
	content, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return append(content, '\n')
}

func serveUnixResponse(t *testing.T, response []byte, contentType string, statusCode int) serverconfig.Profile {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", "vsk-client-")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "control.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.URL.Path != "/api/v1/health" || request.Body == nil {
			t.Errorf("request = %s %s body=%v", request.Method, request.URL.Path, request.Body)
		}
		writer.Header().Set("Content-Type", contentType)
		writer.WriteHeader(statusCode)
		_, _ = writer.Write(response)
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close(); _ = listener.Close(); _ = os.RemoveAll(directory) })
	return serverconfig.Profile{SocketPath: path}
}

func TestStatusPreservesExactValidatedEnvelope(t *testing.T) {
	raw := clientTestEnvelope(t)
	profile := serveUnixResponse(t, raw, "application/json", http.StatusOK)
	response, err := NewClient(clientTestFactory()).Status(context.Background(), profile)
	if err != nil {
		t.Fatal(err)
	}
	if string(response.Raw) != string(raw) || response.ExitCode != 0 || response.Status.State != "ready" || response.Result.RequestID != "request-local" {
		t.Fatalf("Status() = %#v", response)
	}
}

func TestStatusPreservesRemoteFailureEnvelopeAndExit(t *testing.T) {
	status := generated.ServerStatusData{State: "safe-mode", ReadAvailable: true, RecoveryEpoch: 9, StateRevision: 3, RemoteReadState: "disabled", RemoteReadReason: "none"}
	envelope, err := clientTestFactory().Failure(generated.CommandNameServerStatus, generated.RunStatusFailed, generated.ErrorCodeIntegrityFailure, "application-health", false, 9, 3, status)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	raw := append(encoded, '\n')
	profile := serveUnixResponse(t, raw, "application/json", http.StatusServiceUnavailable)
	response, err := NewClient(clientTestFactory()).Status(context.Background(), profile)
	if err != nil {
		t.Fatal(err)
	}
	if response.ExitCode != 8 || string(response.Raw) != string(raw) || response.Result.RequestID != "request-local" {
		t.Fatalf("Status() = %#v", response)
	}
}

func TestStatusRejectsUntrustedResponseShapes(t *testing.T) {
	valid := clientTestEnvelope(t)
	for name, response := range map[string][]byte{
		"trailing":        append(append([]byte(nil), valid...), []byte("{}\n")...),
		"missing newline": valid[:len(valid)-1],
		"oversized":       []byte(`{"private":"` + strings.Repeat("x", maxResponseBodyBytes) + `"}` + "\n"),
		"wrong command":   []byte(strings.Replace(string(valid), `"server status"`, `"help"`, 1)),
	} {
		t.Run(name, func(t *testing.T) {
			profile := serveUnixResponse(t, response, "application/json", http.StatusOK)
			_, err := NewClient(clientTestFactory()).Status(context.Background(), profile)
			stable, ok := failure.As(err)
			if !ok || stable.Code != generated.ErrorCodeIntegrityFailure || stable.Target != "control-service-response" {
				t.Fatalf("Status() error = %v", err)
			}
		})
	}
}

func TestStatusMapsUnavailableSocketWithoutPathLeak(t *testing.T) {
	profile := serverconfig.Profile{SocketPath: filepath.Join(t.TempDir(), "private-canary.sock")}
	_, err := NewClient(clientTestFactory()).Status(context.Background(), profile)
	stable, ok := failure.As(err)
	if !ok || stable.Code != generated.ErrorCodeDependencyUnavailable || !stable.Retryable || strings.Contains(err.Error(), profile.SocketPath) {
		t.Fatalf("Status() error = %v", err)
	}
}

func TestRemoteCommandArgumentsMatchGeneratedOperatorCommands(t *testing.T) {
	want := map[requestSpec][]string{
		{command: generated.CommandNameServerStatus}:                                                                  {"server", "status"},
		{command: "api.v1.summary.get"}:                                                                               {"--output", "json"},
		{command: "api.v1.database-status.get"}:                                                                       {"database", "status"},
		{command: "api.v1.inventory-drafts.import"}:                                                                   {"inventory", "import"},
		{command: "api.v1.inventory-diffs.create"}:                                                                    {"inventory", "diff"},
		{command: "api.v1.inventory-exports.create"}:                                                                  {"inventory", "export"},
		{command: "api.v1.declarations.plan-preparation.get"}:                                                         {"plan"},
		{command: "api.v1.plans.create", path: "/api/v1/declarations/change-1/plans"}:                                 {"--change", "change-1", "--output", "json"},
		{command: "api.v1.plans.get"}:                                                                                 {"apply"},
		{command: "api.v1.plans.execute", path: "/api/v1/plans/plan-1/execute"}:                                       {"--plan-id", "plan-1", "--output", "json"},
		{command: "api.v1.runs.get", path: "/api/v1/runs/run-1"}:                                                      {"--run-id", "run-1", "--output", "json"},
		{command: "api.v1.runs.cancel"}:                                                                               {"run", "cancel"},
		{command: "api.v1.runs.resume"}:                                                                               {"run", "resume"},
		{command: "api.v1.audit-checkpoints.list"}:                                                                    {"audit", "checkpoints"},
		{command: "api.v1.audit-history.verification"}:                                                                {"audit", "verify"},
		{command: "api.v1.backup-offsite-retirements.dry-run"}:                                                        {"backup", "offsite-retirement", "dry-run"},
		{command: "api.v1.backup-offsite-retirements.stage"}:                                                          {"backup", "offsite-retirement", "stage"},
		{command: "api.v1.backup-policy-drafts.create"}:                                                               {"backup", "policy", "draft"},
		{command: "api.v1.backup-retention-lock-drafts.create"}:                                                       {"backup", "retention-locks", "draft"},
		{command: "api.v1.backup-retirement-drafts.create"}:                                                           {"backup", "retirement", "draft"},
		{command: "api.v1.backup-jobs.create"}:                                                                        {"backup", "run"},
		{command: "api.v1.backups.status"}:                                                                            {"backup", "status"},
		{command: "api.v1.backup-verifications.create"}:                                                               {"backup", "verify"},
		{command: "api.v1.database-backups.create"}:                                                                   {"database", "backup"},
		{command: "api.v1.database-exports.create"}:                                                                   {"database", "export"},
		{command: "api.v1.database-restores.create"}:                                                                  {"database", "restore"},
		{command: "api.v1.database-verifications.create"}:                                                             {"database", "verify"},
		{command: "api.v1.gate-evidence.create"}:                                                                      {"gate", "evidence"},
		{command: "api.v1.gates.check", path: "/api/v1/gates/G-008/check"}:                                            {"gate", "check", "--gate-id", "G-008"},
		{command: "api.v1.gates.get", path: "/api/v1/gates/G-008"}:                                                    {"gate", "inspect", "--gate-id", "G-008"},
		{command: "api.v1.gates.list"}:                                                                                {"gate", "list"},
		{command: "api.v1.gate-profile-drafts.create"}:                                                                {"gate", "profile", "draft"},
		{command: "api.v1.restores.plan"}:                                                                             {"restore", "plan"},
		{command: "api.v1.restores.run"}:                                                                              {"restore", "run"},
		{command: "api.v1.restores.verify"}:                                                                           {"restore", "verify"},
		{command: "api.v1.scheduled-job-policies.drafts.create"}:                                                      {"schedule", "policy", "draft"},
		{command: "api.v1.scheduled-job-policies.get", path: "/api/v1/scheduled-job-policies/policy-a"}:               {"schedule", "inspect", "--policy-id", "policy-a"},
		{command: "api.v1.scheduled-job-policies.list"}:                                                               {"schedule", "list"},
		{command: "api.v1.scheduled-jobs.cancel", path: "/api/v1/scheduled-jobs/job-a/cancel"}:                        {"schedule", "cancel", "--job-id", "job-a"},
		{command: "api.v1.scheduled-occurrences.create", path: "/api/v1/scheduled-job-policies/policy-a/occurrences"}: {"schedule", "dispatch", "--policy-id", "policy-a"},
	}
	for spec, expected := range want {
		if got := remoteCommandArguments(spec); !reflect.DeepEqual(got, expected) {
			t.Fatalf("%s arguments = %#v, want %#v", spec.command, got, expected)
		}
	}
	for _, spec := range []requestSpec{
		{command: "api.v1.events.stream"},
		{command: "api.v1.plans.create", path: "/api/v1/declarations/bad/path/plans"},
		{command: "api.v1.plans.execute", path: "/api/v1/plans/plan-1"},
		{command: "api.v1.runs.get", path: "/api/v1/runs/"},
		{command: "api.v1.gates.get", path: "/api/v1/gates/../../private"},
		{command: "api.v1.scheduled-job-policies.get", path: "/api/v1/scheduled-job-policies/"},
		{command: "api.v1.scheduled-occurrences.create", path: "/api/v1/scheduled-job-policies/policy-a"},
		{command: "api.v1.scheduled-jobs.cancel", path: "/api/v1/scheduled-jobs/job-a"},
	} {
		if got := remoteCommandArguments(spec); len(got) != 0 {
			t.Fatalf("disallowed operation arguments = %#v", got)
		}
	}
}
