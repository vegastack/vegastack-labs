//go:build linux

package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/clientfile"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/result"
	"github.com/vegastack/vegastack-labs/internal/server"
)

// The only substitute is the server HTTP boundary. CLI, protected file reading,
// profile loading, Operations delegation and typed transport validation are real.
func hostTransportFixture(t *testing.T, action string) ([]string, []byte, []byte, <-chan string, Option) {
	t.Helper()
	directory, err := os.MkdirTemp("", "ncli-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(directory); err != nil {
			t.Error(err)
		}
	})
	socket := filepath.Join(directory, "control.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(socket, 0600); err != nil {
		t.Fatal(err)
	}
	write := func(path string, value any) {
		t.Helper()
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	config := filepath.Join(directory, "profile.json")
	write(config, generated.ServerProfile{Schema: generated.SchemaIDServerProfile, SchemaVersion: "1.3.0", SocketPath: socket, SocketOwnerUID: int64(os.Geteuid()), SocketMode: "0600", ShutdownGraceSeconds: 5, InventoryExportRoot: directory, PrincipalBindings: []generated.LocalPrincipalBinding{{UID: int64(os.Geteuid()), PrincipalID: "fixture-operator"}}, RemoteRead: generated.RemoteReadProfile{Enabled: false}})
	args := []string{"node", action, "--config", config}
	var request []byte
	var data any
	var schema, route, operation, method string
	digest := "sha256:" + strings.Repeat("a", 64)
	switch action {
	case "discover":
		request = syntheticHostRequest(t, generated.CommandNameNodeDiscover)
		observation := generated.HostObservation{Schema: generated.SchemaIDHostObservation, SchemaVersion: "1.0.0", ObservationID: "observation-a", TargetID: "target-a", TargetRevision: 1, TargetDigest: digest, Collector: "collector-a", CollectorVersion: "1.0.0", ObservedAt: "2026-10-08T00:00:00Z", ExpiresAt: "2026-10-08T00:15:00Z", Status: "incomplete", Facts: []generated.HostDiscoveryFact{}, Blockers: []string{"hardening-unverified"}, ContentDigest: digest}
		data = generated.HostDiscoverySubmission{Schema: generated.SchemaIDHostDiscoverySubmission, SchemaVersion: "1.0.0", Observation: observation, Created: true}
		schema, route, operation, method = generated.SchemaIDHostDiscoverySubmission, "/api/v1/host-observations", "api.v1.host-observations.create", "POST"
	case "add":
		request = syntheticHostRequest(t, generated.CommandNameNodeAdd)
		sum := sha256.Sum256(request)
		content := "sha256:" + hex.EncodeToString(sum[:])
		id := "host-adoption-" + content[7:39]
		data = generated.HostAdoptionSubmission{Schema: generated.SchemaIDHostAdoptionSubmission, SchemaVersion: "1.0.0", DraftID: id, DeclarationID: id, ContentDigest: content}
		schema, route, operation, method = generated.SchemaIDHostAdoptionSubmission, "/api/v1/host-adoptions/draft", "api.v1.host-adoptions.draft", "POST"
	case "inspect":
		data = generated.ManagedHost{Schema: generated.SchemaIDManagedHost, SchemaVersion: "1.0.0", HostID: "host-a", TargetID: "target-a", ObservationID: "observation-a", ProfileID: "profile-a", IdentityClass: "physical", Status: "adopted-unadmitted"}
		schema, route, operation, method = generated.SchemaIDManagedHost, "/api/v1/hosts/host-a", "api.v1.hosts.get", "GET"
		args = append(args, "--host-id", "host-a")
	default:
		t.Fatal("unexpected fixture action")
	}
	rawData, err := json.Marshal(data)
	if err != nil || generated.ValidateContractJSON(schema, rawData, generated.ContractExact) != nil {
		t.Fatalf("invalid transport fixture %s: %v", rawData, err)
	}
	if request != nil {
		file := filepath.Join(directory, "input.json")
		if err := os.WriteFile(file, request, 0600); err != nil {
			t.Fatal(err)
		}
		args = append(args, "--file", file)
	}
	build := result.BuildInfo{ToolVersion: "test", ReleaseBuildID: "test"}
	factory := result.NewFactory(build, func() (string, error) { return "request-host-transport", nil })
	envelope, err := factory.SuccessWithRequestID(operation, "request-host-transport", false, 0, 0, data)
	if err != nil {
		t.Fatal(err)
	}
	response, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	response = append(response, '\n')
	requests := make(chan string, 16)
	httpServer := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- r.Method + " " + r.URL.Path
		if r.Method != method || r.URL.Path != route {
			t.Errorf("unexpected transport request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		if method == "POST" && !bytes.Equal(body, request) {
			t.Errorf("request body changed: %s", body)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(response)
	})}
	go func() { _ = httpServer.Serve(listener) }()
	t.Cleanup(func() { _ = httpServer.Close(); _ = listener.Close() })
	operations := server.NewOperations(build, func() (string, error) { return "request-cli-host", nil })
	return args, request, response, requests, WithControlOperations(operations, clientfile.NewReader())
}

func testNodeCommandThroughTransport(t *testing.T, action string) {
	t.Helper()
	args, _, response, _, option := hostTransportFixture(t, action)
	code, raw, stderr := runTestAppWithOptions(t, context.Background(), append(args, "--output", "json"), nil, option)
	if code != 0 || stderr != "" || raw != string(response) {
		t.Fatalf("transport command code=%d stdout=%s stderr=%s", code, raw, stderr)
	}
}
func TestNodeOutputParityUsesSameServerFacts(t *testing.T) {
	for _, action := range []string{"discover", "add", "inspect"} {
		t.Run(action, func(t *testing.T) {
			args, request, response, _, option := hostTransportFixture(t, action)
			code, human, stderr := runTestAppWithOptions(t, context.Background(), args, nil, option)
			if code != 0 || stderr != "" {
				t.Fatalf("human code=%d stdout=%s stderr=%s", code, human, stderr)
			}
			code, raw, stderr := runTestAppWithOptions(t, context.Background(), append(args, "--output", "json"), nil, option)
			if code != 0 || stderr != "" || raw != string(response) {
				t.Fatalf("JSON code=%d stdout=%s stderr=%s", code, raw, stderr)
			}
			facts := map[string][]string{"discover": {"observation-a", "target-a", "incomplete", "hardening-unverified"}, "inspect": {"host-a", "target-a", "observation-a", "profile-a", "physical", "adopted-unadmitted"}}[action]
			if action == "add" {
				sum := sha256.Sum256(request)
				id := "host-adoption-" + hex.EncodeToString(sum[:])[:32]
				facts = []string{id}
				if !strings.Contains(human, "only prepares") || strings.Contains(human, "No machine has") {
					t.Fatal("inaccurate draft claim", human)
				}
			}
			for _, fact := range facts {
				if !strings.Contains(human, fact) || !strings.Contains(raw, fact) {
					t.Fatalf("missing fact %s human=%s JSON=%s", fact, human, raw)
				}
			}
		})
	}
}
func TestNodeCommandRejectsInputBeforeTransport(t *testing.T) {
	for _, action := range []string{"discover", "add"} {
		for _, variant := range []string{"missing", "malformed", "oversized", "unknown-field"} {
			t.Run(action+"/"+variant, func(t *testing.T) {
				args, raw, _, requests, option := hostTransportFixture(t, action)
				file := args[len(args)-1]
				switch variant {
				case "missing":
					args = args[:len(args)-2]
				case "malformed":
					raw = []byte("{")
				case "oversized":
					raw = append(raw, []byte(strings.Repeat(" ", 16384))...)
				case "unknown-field":
					raw = append([]byte(`{"unknown":true,`), raw[1:]...)
				}
				if err := os.WriteFile(file, raw, 0600); err != nil {
					t.Fatal(err)
				}
				code, _, _ := runTestAppWithOptions(t, context.Background(), append(args, "--output", "json"), nil, option)
				if code != 2 {
					t.Fatalf("expected input rejection, code %d", code)
				}
				select {
				case request := <-requests:
					t.Fatalf("invalid input reached transport: %s", request)
				default:
				}
			})
		}
	}
	t.Run("invalid-host", func(t *testing.T) {
		args, _, _, requests, option := hostTransportFixture(t, "inspect")
		args[len(args)-1] = "../wrong"
		code, _, _ := runTestAppWithOptions(t, context.Background(), append(args, "--output", "json"), nil, option)
		if code != 2 {
			t.Fatalf("code %d", code)
		}
		select {
		case request := <-requests:
			t.Fatalf("invalid ID reached transport: %s", request)
		default:
		}
	})
}
