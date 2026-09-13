package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

type browserResultRecorder struct {
	header http.Header
	body   bytes.Buffer
	status int
}

func (recorder *browserResultRecorder) Header() http.Header { return recorder.header }

func (recorder *browserResultRecorder) WriteHeader(status int) {
	if recorder.status == 0 {
		recorder.status = status
	}
}

func (recorder *browserResultRecorder) Write(value []byte) (int, error) {
	if recorder.status == 0 {
		recorder.status = http.StatusOK
	}
	return recorder.body.Write(value)
}

// projectBrowserResults keeps the server's request correlation available to
// audit, CLI, and executor paths while removing it from the browser boundary.
// SSE already has its own generated safe event projection and must stream.
func projectBrowserResults(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/api/v1/events" {
			next.ServeHTTP(writer, request)
			return
		}
		recorder := &browserResultRecorder{header: make(http.Header)}
		next.ServeHTTP(recorder, request)
		status := recorder.status
		if status == 0 {
			status = http.StatusOK
		}
		body := recorder.body.Bytes()
		if strings.HasPrefix(strings.ToLower(recorder.header.Get("Content-Type")), "application/json") {
			var internal generated.RunResult
			if json.Unmarshal(body, &internal) != nil || internal.Schema != generated.SchemaIDRunResult || internal.RequestID == "" {
				http.Error(writer, generated.ErrorCodeIntegrityFailure, http.StatusInternalServerError)
				return
			}
			safe := generated.BrowserRunResult{
				Schema: generated.SchemaIDBrowserRunResult, SchemaVersion: internal.SchemaVersion,
				ToolVersion: internal.ToolVersion, Command: internal.Command, RunID: internal.RunID,
				Status: internal.Status, Changed: internal.Changed, RecoveryEpoch: internal.RecoveryEpoch,
				StateRevision: internal.StateRevision, SnapshotDigest: internal.SnapshotDigest,
				ReleaseBuildID: internal.ReleaseBuildID, SourceRevision: internal.SourceRevision,
				PlanID: internal.PlanID, Errors: internal.Errors, Data: internal.Data,
			}
			var err error
			body, err = json.Marshal(safe)
			if err != nil {
				http.Error(writer, generated.ErrorCodeIntegrityFailure, http.StatusInternalServerError)
				return
			}
			body = append(body, '\n')
		}
		for name, values := range recorder.header {
			if strings.EqualFold(name, "Content-Length") {
				continue
			}
			writer.Header()[name] = append([]string(nil), values...)
		}
		writer.Header().Set("Content-Length", strconv.Itoa(len(body)))
		writer.WriteHeader(status)
		if request.Method != http.MethodHead {
			_, _ = writer.Write(body)
		}
	})
}
