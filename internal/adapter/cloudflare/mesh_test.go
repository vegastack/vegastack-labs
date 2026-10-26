package cloudflare

import (
	"context"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	mesh "github.com/vegastack/vegastack-labs/internal/networkmesh"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testUUID = "11111111-1111-4111-8111-111111111111"

func testChange() generated.MeshChange {
	return generated.MeshChange{Schema: generated.SchemaIDMeshChange, SchemaVersion: "1.0.0", Mode: "foundation", ProfileID: "mesh-pilot", AccountID: strings.Repeat("a", 32), ResourceID: testUUID, ResourceKind: "profile-include", Action: "profile-routing-update", OwnerID: "human-a", DeviceID: "device-a", PhysicalDeviceID: testUUID, ProviderUserID: testUUID, ExpectedOwnershipRevision: 1, BeforeDigest: mesh.Digest(nil), MeshCIDR: "100.96.0.0/12", Routes: []generated.MeshRoute{{Schema: generated.SchemaIDMeshRoute, SchemaVersion: "1.0.0", Address: "10.0.0.0/24"}, {Schema: generated.SchemaIDMeshRoute, SchemaVersion: "1.0.0", Address: "100.96.0.0/12"}}, AffectedIdentityDigests: []string{mesh.Digest("synthetic-host")}, RuleAction: "allow", RuleName: "mesh-rule", Traffic: "net.dst.ip == 10.0.0.1", RuleIdentity: "identity.email == \"synthetic@example.invalid\"", ObservationReferenceID: "read-ref", MutationReferenceID: "write-ref"}
}
func testValue(t *testing.T, s string) *credentialref.Value {
	t.Helper()
	v, e := credentialref.NewValue([]byte(s))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(v.Close)
	return v
}

type fixtureAuthority struct {
	d       mesh.Staged
	denied  bool
	records []string
	reads   int
}

func (a *fixtureAuthority) Resolve(context.Context, adapter.Operation, adapter.ExactExecutionBinding) (mesh.Staged, error) {
	if a.denied {
		return mesh.Staged{}, mesh.Error(generated.ErrorCodeAuthorizationDenied)
	}
	return a.d, nil
}
func (a *fixtureAuthority) BorrowRead(context.Context, mesh.Staged) (*credentialref.Value, error) {
	a.reads++
	return credentialref.NewValue([]byte("fixture-observer"))
}
func (a *fixtureAuthority) Record(_ context.Context, _ mesh.Staged, _ adapter.ExactExecutionBinding, _ mesh.Snapshot, s string) error {
	a.records = append(a.records, s)
	return nil
}
func TestMeshBoundSDKRereadsAndPreservesRoutes(t *testing.T) {
	writes, gets := 0, 0
	added := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == "GET" {
			gets++
			if r.Header.Get("Authorization") != "Bearer fixture-observer" {
				t.Error("wrong observation credential")
			}
			routes := []map[string]string{{"address": "10.0.0.0/24"}}
			if added {
				routes = append(routes, map[string]string{"address": "100.96.0.0/12"})
			}
			json.NewEncoder(w).Encode(map[string]any{"success": true, "result": routes})
			return
		}
		writes++
		if r.Method != "PUT" || r.Header.Get("Authorization") != "Bearer fixture-mutator" {
			t.Error("wrong mutation call")
		}
		var body []map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		if len(body) != 2 || body[0]["address"] != "10.0.0.0/24" {
			t.Error("unrelated route lost")
		}
		added = true
		json.NewEncoder(w).Encode(map[string]any{"success": true, "result": body})
	}))
	defer srv.Close()
	sdk := &SDKClient{transport: srv.Client().Transport, base: srv.URL + "/"}
	q := testChange()
	before, e := sdk.Observe(context.Background(), q, testValue(t, "fixture-observer"))
	if e != nil {
		t.Fatal(e)
	}
	q.BeforeDigest = before.Digest
	authority := &fixtureAuthority{d: mesh.Staged{Request: generated.MeshDraftRequest{Change: q}, Bindings: []credentialref.StepBinding{{PurposeID: mesh.PurposeRead}, {PurposeID: mesh.PurposeWrite}}}}
	a := &MeshAdapter{Authority: authority, Backend: sdk}
	op := adapter.Operation{OperationID: "mesh-change", OperationType: "network.mesh.profile-routing-update", AdapterID: mesh.AdapterID, ExecutorID: "central", TargetID: q.ProfileID, InputDigest: mesh.Digest("bindings"), ArtifactDigest: mesh.Digest(q)}
	b := adapter.ExactExecutionBinding{RunID: "run-a", StepID: "step-a"}
	effect, e := a.ExecuteBoundWithCredentials(context.Background(), op, b, []*credentialref.Value{testValue(t, "fixture-observer"), testValue(t, "fixture-mutator")})
	if e != nil || effect.Status != "succeeded" {
		t.Fatalf("effect %+v %v", effect, e)
	}
	v, e := a.Verify(context.Background(), op, effect)
	if e != nil || !v.Verified || writes != 1 || gets != 4 || authority.reads != 1 || len(authority.records) != 1 {
		t.Fatalf("verification %+v err %v writes %d gets %d records %v", v, e, writes, gets, authority.records)
	}
}
func TestMeshDeniedBeforeHTTP(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls++ }))
	defer srv.Close()
	a := &MeshAdapter{Authority: &fixtureAuthority{denied: true}, Backend: &SDKClient{transport: srv.Client().Transport, base: srv.URL + "/"}}
	_, e := a.ExecuteBoundWithCredentials(context.Background(), adapter.Operation{OperationID: "mesh-change", OperationType: "network.mesh.import", AdapterID: mesh.AdapterID, ExecutorID: "central", TargetID: "pilot", InputDigest: mesh.Digest(nil), ArtifactDigest: mesh.Digest(nil)}, adapter.ExactExecutionBinding{}, nil)
	if e == nil || calls != 0 {
		t.Fatalf("denied effect called provider %d %v", calls, e)
	}
}
func TestSDKRejectsSuccessFalseAndCursorLoop(t *testing.T) {
	for _, body := range []string{`{"success":false,"errors":[{"message":"fixture-secret-must-not-escape"}]}`, `{"success":true,"result":[],"result_info":{"cursor":"repeated"}}`, `{"success":true,"result":[],"result_info":{"cursor":"","total_count":1}}`} {
		t.Run(body, func(t *testing.T) {
			calls := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.Write([]byte(body)) }))
			defer srv.Close()
			q := testChange()
			q.ResourceKind = "registration"
			q.Action = "import"
			sdk := &SDKClient{transport: srv.Client().Transport, base: srv.URL + "/"}
			_, e := sdk.Observe(context.Background(), q, testValue(t, "fixture-observer"))
			if e == nil || strings.Contains(e.Error(), "fixture-secret") || calls > 2 {
				t.Fatalf("unbounded/unsafe envelope %d %v", calls, e)
			}
		})
	}
}
func TestSDKMutationResponseLossNoReplay(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		conn, _, _ := w.(http.Hijacker).Hijack()
		conn.Close()
	}))
	defer srv.Close()
	sdk := &SDKClient{transport: srv.Client().Transport, base: srv.URL + "/"}
	e := sdk.Mutate(context.Background(), testChange(), testValue(t, "fixture-mutator"))
	if e == nil || calls != 1 {
		t.Fatalf("response loss replayed %d %v", calls, e)
	}
}
func TestRouteRemovalOnlyPermitsDeclaredMeshRange(t *testing.T) {
	r := func(s string) generated.MeshRoute { return generated.MeshRoute{Address: s} }
	if preservesRoutes([]generated.MeshRoute{r("10.0.0.0/24")}, nil, "100.96.0.0/12") {
		t.Fatal("unrelated route removal allowed")
	}
	if !preservesRoutes([]generated.MeshRoute{r("10.0.0.0/24"), r("100.96.0.0/12")}, []generated.MeshRoute{r("10.0.0.0/24")}, "100.96.0.0/12") {
		t.Fatal("declared Mesh range could not be removed")
	}
}
