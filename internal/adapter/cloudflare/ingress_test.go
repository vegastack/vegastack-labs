package cloudflare

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
	ingress "github.com/vegastack/vegastack-labs/internal/networkingress"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func ingressTestChange() generated.IngressChange {
	return generated.IngressChange{ProfileID: "ingress-pilot", AccountID: strings.Repeat("a", 32), ZoneID: strings.Repeat("b", 32), TunnelID: testUUID, ResourceID: testUUID, ResourceKind: "connector", Action: "connector-disconnect", Hostname: "synthetic.ingress.invalid", OriginService: "https://10.0.0.1:443", OriginServerName: "synthetic.origin.invalid", AccessAppID: testUUID, AccessPolicyID: testUUID, DNSRecordID: strings.Repeat("c", 32), ConnectorID: testUUID, AllowedGroupIDs: []string{testUUID}, PolicyName: "synthetic", Connectors: []generated.IngressConnectorTarget{{ConnectorID: testUUID, HostID: "synthetic-connector", IdentityDigest: ingress.Digest("synthetic")}}}
}
func TestIngressDisconnectAlwaysNamesClientID(t *testing.T) {
	calls := 0
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		if r.Method != "DELETE" || r.URL.Query().Get("client_id") != testUUID {
			t.Error("disconnect widened or used wrong method")
		}
		w.Write([]byte(`{"success":true,"result":null}`))
	}))
	defer s.Close()
	c := &SDKClient{transport: s.Client().Transport, base: s.URL + "/"}
	q := ingressTestChange()
	if e := c.MutateIngress(context.Background(), q, testValue(t, "fixture-mutator"), nil); e != nil {
		t.Fatal(e)
	}
	q.ConnectorID = ""
	if e := c.MutateIngress(context.Background(), q, testValue(t, "fixture-mutator"), nil); e == nil || calls != 1 {
		t.Fatal("empty connector became all-connectors mutation")
	}
}
func TestIngressTunnelConfigPreservesUnownedFields(t *testing.T) {
	q := ingressTestChange()
	q.Action = "tunnel-config-update"
	q.ResourceKind = "tunnel-configuration"
	config := map[string]any{"originRequest": map[string]any{"connectTimeout": 17}, "ingress": []any{map[string]any{"hostname": q.Hostname, "service": "https://10.0.0.2:443", "originRequest": map[string]any{"originServerName": "old.invalid", "connectTimeout": 19}}, map[string]any{"hostname": "other.invalid", "service": "https://10.0.0.3:443", "path": "^/retained"}, map[string]any{"service": "http_status:404"}}}
	q.BeforeDigest = ingressDigest(q, ingress.Snapshot{StateDigest: ingress.Digest(config)})
	puts := 0
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == "GET" {
			json.NewEncoder(w).Encode(map[string]any{"success": true, "result": map[string]any{"tunnel_id": q.TunnelID, "source": "cloudflare", "config": config}})
			return
		}
		puts++
		var body struct {
			Config map[string]any `json:"config"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			t.Fatal("invalid body")
		}
		rules := body.Config["ingress"].([]any)
		if len(rules) != 3 || rules[1].(map[string]any)["path"] != "^/retained" || rules[2].(map[string]any)["service"] != "http_status:404" {
			t.Error("unowned route/catch-all changed")
		}
		origin := rules[0].(map[string]any)["originRequest"].(map[string]any)
		if origin["noTLSVerify"] != false || origin["originServerName"] != q.OriginServerName || origin["connectTimeout"] != float64(19) {
			t.Error("origin TLS/retained settings changed")
		}
		json.NewEncoder(w).Encode(map[string]any{"success": true, "result": map[string]any{"config": body.Config}})
	}))
	defer s.Close()
	c := &SDKClient{transport: s.Client().Transport, base: s.URL + "/"}
	if e := c.MutateIngress(context.Background(), q, testValue(t, "fixture-mutator"), nil); e != nil || puts != 1 {
		t.Fatalf("config update %v calls=%d", e, puts)
	}
}
func TestIngressTokenSecretNeverUsesTokenGetEndpoint(t *testing.T) {
	calls := 0
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		if r.Method != "PATCH" || strings.Contains(r.URL.Path, "/token") {
			t.Error("unexpected token retrieval or mutation")
		}
		var body map[string]string
		if json.NewDecoder(r.Body).Decode(&body) != nil || body["tunnel_secret"] == "" {
			t.Error("replacement secret not used")
		}
		w.Write([]byte(`{"success":true,"result":{"id":"11111111-1111-4111-8111-111111111111"}}`))
	}))
	defer s.Close()
	q := ingressTestChange()
	q.Action = "token-rotate"
	c := &SDKClient{transport: s.Client().Transport, base: s.URL + "/"}
	replacement := testValue(t, base64.StdEncoding.EncodeToString([]byte(strings.Repeat("s", 32))))
	if e := c.MutateIngress(context.Background(), q, testValue(t, "fixture-mutator"), replacement); e != nil || calls != 1 {
		t.Fatalf("rotation request %v calls=%d", e, calls)
	}
}
func TestIngressCannotVerifyTLSBypassAsConfigured(t *testing.T) {
	q := ingressTestChange()
	q.Action = "tunnel-config-update"
	s := ingress.Snapshot{Present: true, Hostname: q.Hostname, OriginService: q.OriginService, OriginServerName: q.OriginServerName, OriginTLSVerified: false}
	if matchesIngress(q, s) {
		t.Fatal("TLS bypass reported as verified configuration")
	}
}
