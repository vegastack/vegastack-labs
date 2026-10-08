package localapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"strings"
	"testing"
)

func TestHostClientRejectsInvalidHostBeforeTransport(t *testing.T) {
	profile, captured := serveGateCheckResponses(t, "G-001", nil, nil)
	_, err := NewClient(clientTestFactory()).GetManagedHost(context.Background(), profile, "../other-host")
	stable, ok := failure.As(err)
	if !ok || stable.Code != generated.ErrorCodeInputInvalid || stable.Target != "host-id" {
		t.Fatalf("expected host-id rejection: %v", err)
	}
	select {
	case request := <-captured:
		t.Fatalf("unexpected transport: %+v", request)
	default:
	}
}

func TestHostClientInspectBinding(t *testing.T) {
	for _, variant := range []string{"valid", "host", "revision", "epoch"} {
		t.Run(variant, func(t *testing.T) {
			h := generated.ManagedHost{Schema: generated.SchemaIDManagedHost, SchemaVersion: "1.0.0", HostID: "host-a", TargetID: "target-a", ObservationID: "observation-a", ProfileID: "profile-a", IdentityClass: "physical", Status: "adopted-unadmitted", StateRevision: 7, RecoveryEpoch: 2}
			switch variant {
			case "host":
				h.HostID = "host-b"
			case "revision":
				h.StateRevision++
			case "epoch":
				h.RecoveryEpoch++
			}
			_, profile, captured := serveFixedResponse(t, 200, operationEnvelope(t, "api.v1.hosts.get", false, 2, 7, h))
			response, err := NewClient(clientTestFactory()).GetManagedHost(context.Background(), profile, "host-a")
			req := <-captured
			if req.method != "GET" || req.path != "/api/v1/hosts/host-a" {
				t.Fatalf("wrong route: %+v", req)
			}
			if variant == "valid" {
				if err != nil || response.Data.Status != "adopted-unadmitted" {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("accepted mismatched response")
			}
		})
	}
}

func TestHostClientDiscoveryBindings(t *testing.T) {
	input := generated.HostDiscoveryRequest{Schema: generated.SchemaIDHostDiscoveryRequest, SchemaVersion: "1.0.0", TargetID: "target-a", TargetRevision: 1, ExpectedStateRevision: 7, RecoveryEpoch: 2, IdempotencyKey: "scan-a"}
	for _, variant := range []string{"valid", "target", "target-revision", "revision", "epoch"} {
		t.Run(variant, func(t *testing.T) {
			o := generated.HostObservation{Schema: generated.SchemaIDHostObservation, SchemaVersion: "1.0.0", ObservationID: "observation-a", TargetID: "target-a", TargetRevision: 1, TargetDigest: "sha256:" + strings.Repeat("a", 64), Collector: "collector-a", CollectorVersion: "1.0.0", ObservedAt: "2026-10-08T00:00:00Z", ExpiresAt: "2026-10-08T00:15:00Z", Status: "incomplete", Facts: []generated.HostDiscoveryFact{}, Blockers: []string{"hardening-unverified"}, ContentDigest: "sha256:" + strings.Repeat("b", 64), StateRevision: 7, RecoveryEpoch: 2}
			switch variant {
			case "target":
				o.TargetID = "target-b"
			case "target-revision":
				o.TargetRevision++
			case "revision":
				o.StateRevision++
			case "epoch":
				o.RecoveryEpoch++
			}
			_, profile, captured := serveFixedResponse(t, 200, operationEnvelope(t, "api.v1.host-observations.create", false, 2, 7, generated.HostDiscoverySubmission{Schema: generated.SchemaIDHostDiscoverySubmission, SchemaVersion: "1.0.0", Observation: o, Created: true}))
			_, err := NewClient(clientTestFactory()).DiscoverHost(context.Background(), profile, input)
			req := <-captured
			if req.path != "/api/v1/host-observations" || req.method != "POST" {
				t.Fatalf("wrong route %+v", req)
			}
			if variant == "valid" && err != nil {
				t.Fatal(err)
			}
			if variant != "valid" && err == nil {
				t.Fatal("accepted mismatch")
			}
		})
	}
}
func TestHostClientAdoptionBinding(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	input := generated.HostAdoptionRequest{Schema: generated.SchemaIDHostAdoptionRequest, SchemaVersion: "1.0.0", HostID: "host-a", ObservationID: "observation-a", ObservationDigest: digest, IdempotencyKey: "add-a", ExpectedStateRevision: 7, RecoveryEpoch: 2, Confirmation: generated.HostIdentityConfirmation{Schema: generated.SchemaIDHostIdentityConfirmation, SchemaVersion: "1.0.0", TargetDigest: digest, TargetRevision: 1, IdentityDigest: digest, IdentityClass: "physical", IdentityKind: "product-serial", ConfirmedAt: "2026-10-08T00:00:00Z"}}
	raw, _ := json.Marshal(input)
	hash := sha256.Sum256(raw)
	content := "sha256:" + hex.EncodeToString(hash[:])
	id := "host-adoption-" + content[7:39]
	for _, variant := range []string{"valid", "digest", "id", "revision", "epoch"} {
		t.Run(variant, func(t *testing.T) {
			data := generated.HostAdoptionSubmission{Schema: generated.SchemaIDHostAdoptionSubmission, SchemaVersion: "1.0.0", DraftID: id, DeclarationID: id, ContentDigest: content, StateRevision: 8, RecoveryEpoch: 2}
			switch variant {
			case "digest":
				data.ContentDigest = digest
			case "id":
				data.DeclarationID = "other"
			case "revision":
				data.StateRevision++
			case "epoch":
				data.RecoveryEpoch++
			}
			_, profile, captured := serveFixedResponse(t, 200, operationEnvelope(t, "api.v1.host-adoptions.draft", false, 2, 8, data))
			_, err := NewClient(clientTestFactory()).SubmitHostAdoption(context.Background(), profile, input)
			req := <-captured
			if req.path != "/api/v1/host-adoptions/draft" || req.method != "POST" || !bytes.Equal(req.body, raw) {
				t.Fatalf("wrong request %+v", req)
			}
			if variant == "valid" && err != nil {
				t.Fatal(err)
			}
			if variant != "valid" && err == nil {
				t.Fatal("accepted mismatch")
			}
		})
	}
}

func TestHostClientPreservesDenial(t *testing.T) {
	for _, code := range []string{generated.ErrorCodeAuthorizationDenied, generated.ErrorCodePrerequisiteBlocked} {
		t.Run(code, func(t *testing.T) {
			e, err := clientTestFactory().Failure("api.v1.hosts.get", generated.RunStatusFailed, code, "read", false, 2, 7, struct{}{})
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := json.Marshal(e)
			raw = append(raw, '\n')
			_, profile, captured := serveFixedResponse(t, expectedHTTPStatus(code), raw)
			response, err := NewClient(clientTestFactory()).GetManagedHost(context.Background(), profile, "host-a")
			<-captured
			if err != nil || response.ExitCode != generated.ErrorExitCodes[code] || !bytes.Equal(response.Raw, raw) || response.Result.StateRevision != 7 {
				t.Fatalf("failure changed %+v %v", response, err)
			}
		})
	}
}
