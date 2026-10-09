package localapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"os"
	"strings"
	"testing"
)

func TestHostLifecycleClientRejectsInvalidBeforeTransport(t *testing.T) {
	profile, captured := serveGateCheckResponses(t, "G-001", nil, nil)
	client := NewClient(clientTestFactory())
	calls := []func() error{
		func() error {
			_, e := client.PrepareHostTarget(context.Background(), profile, generated.HostDiscoveryTargetDraftRequest{})
			return e
		},
		func() error {
			_, e := client.SubmitHostAction(context.Background(), profile, generated.HostActionRequest{})
			return e
		},
		func() error {
			_, e := client.SubmitHostAccess(context.Background(), profile, generated.HostAccessDraftRequest{})
			return e
		},
		func() error { _, e := client.GetHostObservation(context.Background(), profile, "../outside"); return e },
	}
	for i, call := range calls {
		if call() == nil {
			t.Fatalf("invalid request %d accepted", i)
		}
	}
	select {
	case request := <-captured:
		t.Fatalf("invalid request reached transport: %+v", request)
	default:
	}
}

func TestHostLifecyclePreparedResponseBindings(t *testing.T) {
	for _, kind := range []string{"target", "action", "access"} {
		for _, mode := range []string{"valid", "draft", "declaration", "digest-binding", "epoch", "revision", "stale-state"} {
			t.Run(kind+"/"+mode, func(t *testing.T) {
				raw, err := os.ReadFile("testdata/host-" + kind + ".json")
				if err != nil {
					t.Fatal(err)
				}
				var input any
				switch kind {
				case "target":
					input = &generated.HostDiscoveryTargetDraftRequest{}
				case "action":
					input = &generated.HostActionRequest{}
				case "access":
					input = &generated.HostAccessDraftRequest{}
				}
				if json.Unmarshal(raw, input) != nil {
					t.Fatal("fixture")
				}
				canonical, _ := json.Marshal(input)
				sum := sha256.Sum256(canonical)
				digest := "sha256:" + hex.EncodeToString(sum[:])
				prefix := "host-" + kind + "-"
				operation := "api.v1.host-" + kind + "s.draft"
				route := "/api/v1/host-" + kind + "s/draft"
				if kind == "target" {
					prefix = "discovery-draft-"
					operation = "api.v1.host-discovery-targets.draft"
					route = "/api/v1/host-discovery-targets/draft"
				}
				if kind == "access" {
					operation = "api.v1.host-access.draft"
					route = "/api/v1/host-access/draft"
				}
				id := prefix + digest[7:39]
				data := generated.HostActionSubmission{Schema: generated.SchemaIDHostActionSubmission, SchemaVersion: "1.0.0", DraftID: id, DeclarationID: id, ContentDigest: digest, StateRevision: 3}
				responseState := int64(3)
				switch mode {
				case "draft":
					data.DraftID = "other"
				case "declaration":
					data.DeclarationID = "other"
				case "digest-binding":
					data.ContentDigest = "sha256:" + strings.Repeat("f", 64)
				case "epoch":
					data.RecoveryEpoch = 1
				case "revision":
					data.StateRevision = 4
				case "stale-state":
					data.StateRevision = 0
					responseState = 0
				}
				var payload any = data
				if kind == "target" {
					payload = generated.HostDiscoveryTargetDraftSubmission{Schema: generated.SchemaIDHostDiscoveryTargetDraftSubmission, SchemaVersion: "1.0.0", DraftID: data.DraftID, DeclarationID: data.DeclarationID, ContentDigest: data.ContentDigest, StateRevision: data.StateRevision, RecoveryEpoch: data.RecoveryEpoch}
				}
				_, profile, captured := serveFixedResponse(t, 200, operationEnvelope(t, operation, false, 0, responseState, payload))
				client := NewClient(clientTestFactory())
				switch value := input.(type) {
				case *generated.HostDiscoveryTargetDraftRequest:
					_, err = client.PrepareHostTarget(context.Background(), profile, *value)
				case *generated.HostActionRequest:
					_, err = client.SubmitHostAction(context.Background(), profile, *value)
				case *generated.HostAccessDraftRequest:
					_, err = client.SubmitHostAccess(context.Background(), profile, *value)
				}
				if mode == "valid" && err != nil {
					t.Fatal(err)
				}
				if mode != "valid" && err == nil {
					t.Fatal("mismatched response accepted")
				}
				select {
				case req := <-captured:
					if req.method != "POST" || req.path != route || !bytes.Equal(req.body, canonical) {
						t.Fatalf("wrong exact request %+v", req)
					}
				default:
					t.Fatal("valid request did not reach transport")
				}
				select {
				case <-captured:
					t.Fatal("mutation retried")
				default:
				}
			})
		}
	}
}
