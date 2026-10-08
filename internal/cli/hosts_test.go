package cli

import (
	"context"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localapi"
	"strings"
	"testing"
)

func syntheticHostRequest(t *testing.T, command string) []byte {
	t.Helper()
	var input any
	if command == generated.CommandNameNodeDiscover {
		input = generated.HostDiscoveryRequest{Schema: generated.SchemaIDHostDiscoveryRequest, SchemaVersion: "1.0.0", TargetID: "target-a", TargetRevision: 1, IdempotencyKey: "scan-a"}
	} else {
		d := "sha256:" + strings.Repeat("a", 64)
		input = generated.HostAdoptionRequest{Schema: generated.SchemaIDHostAdoptionRequest, SchemaVersion: "1.0.0", HostID: "host-a", ObservationID: "observation-a", ObservationDigest: d, IdempotencyKey: "add-a", Confirmation: generated.HostIdentityConfirmation{Schema: generated.SchemaIDHostIdentityConfirmation, SchemaVersion: "1.0.0", TargetDigest: d, TargetRevision: 1, IdentityDigest: d, IdentityKind: "product-serial", IdentityClass: "physical", ConfirmedAt: "2026-10-08T00:00:00Z"}}
	}
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func (stub *stubControlOperations) DiscoverHost(_ context.Context, _ string, _ generated.HostDiscoveryRequest) (localapi.TypedResponse[generated.HostDiscoverySubmission], error) {
	stub.calls++
	return stub.hostDiscoveryResponse, stub.err
}
func (stub *stubControlOperations) SubmitHostAdoption(_ context.Context, _ string, _ generated.HostAdoptionRequest) (localapi.TypedResponse[generated.HostAdoptionSubmission], error) {
	stub.calls++
	return stub.hostAdoptionResponse, stub.err
}
func (stub *stubControlOperations) GetManagedHost(_ context.Context, _, _ string) (localapi.TypedResponse[generated.ManagedHost], error) {
	stub.calls++
	return stub.hostInspectResponse, stub.err
}
func TestNodeCommandRejectsInputBeforeClient(t *testing.T) {
	for _, action := range []string{"discover", "add"} {
		for _, variant := range []string{"missing", "malformed", "oversized", "unknown-field"} {
			t.Run(action+"/"+variant, func(t *testing.T) {
				stub := successfulControlOperations(t)
				raw := syntheticHostRequest(t, "node "+action)
				args := []string{"node", action, "--config", "profile.json", "--file", "input.json", "--output", "json"}
				switch variant {
				case "missing":
					args = []string{"node", action, "--config", "profile.json", "--output", "json"}
				case "malformed":
					raw = []byte("{")
				case "oversized":
					raw = append(raw, []byte(strings.Repeat(" ", 16384))...)
				case "unknown-field":
					raw = append([]byte(`{"unknown":true,`), raw[1:]...)
				}
				code, _, _ := runTestAppWithOptions(t, context.Background(), args, nil, WithControlOperations(stub, &stubFileReader{content: raw}))
				if code != 2 || stub.calls != 0 {
					t.Fatalf("code %d calls %d", code, stub.calls)
				}
			})
		}
	}
	stub := successfulControlOperations(t)
	code, _, _ := runTestAppWithOptions(t, context.Background(), []string{"node", "inspect", "--config", "profile.json", "--host-id", "../wrong", "--output", "json"}, nil, WithControlOperations(stub, nil))
	if code != 2 || stub.calls != 0 {
		t.Fatalf("invalid ID code %d calls %d", code, stub.calls)
	}
}
