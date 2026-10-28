package cloudflare

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
	ingress "github.com/vegastack/vegastack-labs/internal/networkingress"
)

func bootstrapTestChange(action string) generated.IngressChange {
	q := ingressTestChange()
	q.Action, q.ResourceKind, q.ResourceID = action, ingress.BootstrapKind(action), ""
	q.OwnerID, q.DeviceID = "operator-a", "device-a"
	q.PolicyName = "labs-console"
	q.BeforeDigest, q.OriginIdentityDigest = ingress.Digest("before"), ingress.Digest("certificate")
	q.ObservationReferenceID, q.MutationReferenceID = "observer", "mutator"
	q.ExpectedOwnershipRevision = 0
	q.Bootstrap = &generated.IngressBootstrap{Name: "labs-console", AllowedEmail: "operator@example.test", SourceRunIDs: []string{}}
	q.Connectors[0].ConnectorID = ""
	q.TunnelID, q.AccessAppID, q.AccessPolicyID, q.AllowedGroupIDs = "", "", "", nil
	for _, stage := range ingress.BootstrapNeeds(action) {
		q.Bootstrap.SourceRunIDs = append(q.Bootstrap.SourceRunIDs, stage+"-run")
	}
	return q
}

func bootstrapTestClient(t *testing.T, handler http.HandlerFunc) *SDKClient {
	t.Helper()
	s := httptest.NewServer(handler)
	t.Cleanup(s.Close)
	return &SDKClient{transport: s.Client().Transport, base: s.URL + "/"}
}

func bootstrapReply(w http.ResponseWriter, result any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": result})
}

func TestBootstrapTunnelCreationUsesReadThenWriteAndDiscardsSecrets(t *testing.T) {
	q := bootstrapTestChange("bootstrap-tunnel")
	posts := 0
	c := bootstrapTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			if strings.HasSuffix(r.URL.Path, "/"+testUUID) {
				bootstrapReply(w, map[string]any{"id": testUUID, "name": q.Bootstrap.Name, "config_src": "cloudflare"})
				return
			}
			if r.URL.Query().Get("name") != q.Bootstrap.Name || r.Header.Get("Authorization") != "Bearer fixture-observer" {
				t.Error("absence check lost exact name or observation credential")
			}
			bootstrapReply(w, []any{})
			return
		}
		posts++
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer fixture-mutator" || body["name"] != q.Bootstrap.Name || body["config_src"] != "cloudflare" || body["tunnel_secret"] != nil {
			t.Error("creation widened scope or exposed a supplied secret")
		}
		bootstrapReply(w, map[string]any{"id": testUUID, "name": q.Bootstrap.Name, "config_src": "cloudflare", "token": "must-never-escape", "credentials_file": map[string]any{"TunnelSecret": "also-secret"}})
	})
	before, err := c.ObserveBootstrap(context.Background(), q, testValue(t, "fixture-observer"))
	if err != nil || before.Present || before.Digest == "" {
		t.Fatalf("absence: %+v %v", before, err)
	}
	q.BeforeDigest = before.Digest
	after, err := c.MutateBootstrap(context.Background(), q, testValue(t, "fixture-observer"), testValue(t, "fixture-mutator"))
	b, _ := json.Marshal(after)
	if err != nil || posts != 1 || after.ResourceID != testUUID || strings.Contains(string(b), "secret") || strings.Contains(string(b), "token") {
		t.Fatalf("create receipt leaked or failed: %s %v posts=%d", b, err, posts)
	}
}

func TestBootstrapConflictingNameNeverCreatesOrAdopts(t *testing.T) {
	q := bootstrapTestChange("bootstrap-tunnel")
	posts := 0
	c := bootstrapTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			posts++
		}
		bootstrapReply(w, []any{map[string]any{"id": testUUID, "name": q.Bootstrap.Name}})
	})
	if _, err := c.MutateBootstrap(context.Background(), q, testValue(t, "fixture-observer"), testValue(t, "fixture-mutator")); err == nil || posts != 0 {
		t.Fatalf("conflict adopted or mutated: %v posts=%d", err, posts)
	}
}

func TestBootstrapLostCreateResponseIsNotAutomaticallyRetried(t *testing.T) {
	q := bootstrapTestChange("bootstrap-tunnel")
	posts := 0
	c := bootstrapTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			bootstrapReply(w, []any{})
			return
		}
		posts++
		w.WriteHeader(http.StatusBadGateway)
		_, _ = io.WriteString(w, `{"success":false,"errors":[{"message":"sensitive provider detail"}]}`)
	})
	before, _ := c.ObserveBootstrap(context.Background(), q, testValue(t, "fixture-observer"))
	q.BeforeDigest = before.Digest
	_, err := c.MutateBootstrap(context.Background(), q, testValue(t, "fixture-observer"), testValue(t, "fixture-mutator"))
	if err == nil || posts != 1 || strings.Contains(err.Error(), "sensitive") {
		t.Fatalf("ambiguous create retried or raw error escaped: %v posts=%d", err, posts)
	}
}

func TestBootstrapEmailGroupIsExactAndNotDefault(t *testing.T) {
	q := bootstrapTestChange("bootstrap-group")
	posts := 0
	c := bootstrapTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			if strings.HasSuffix(r.URL.Path, "/"+testUUID) {
				bootstrapReply(w, map[string]any{"id": testUUID, "name": q.Bootstrap.Name, "include": []any{map[string]any{"email": map[string]any{"email": q.Bootstrap.AllowedEmail}}}})
				return
			}
			bootstrapReply(w, []any{})
			return
		}
		posts++
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		include, _ := body["include"].([]any)
		if len(include) != 1 || include[0].(map[string]any)["email"].(map[string]any)["email"] != q.Bootstrap.AllowedEmail || body["is_default"] == true {
			t.Error("group permission widened")
		}
		bootstrapReply(w, map[string]any{"id": testUUID, "name": q.Bootstrap.Name, "include": include})
	})
	before, _ := c.ObserveBootstrap(context.Background(), q, testValue(t, "fixture-observer"))
	q.BeforeDigest = before.Digest
	after, err := c.MutateBootstrap(context.Background(), q, testValue(t, "fixture-observer"), testValue(t, "fixture-mutator"))
	if err != nil || posts != 1 || after.ResourceID != testUUID {
		t.Fatalf("group: %+v %v posts=%d", after, err, posts)
	}
}

func TestBootstrapStaleBeforeStateNeverWrites(t *testing.T) {
	q := bootstrapTestChange("bootstrap-tunnel")
	posts := 0
	c := bootstrapTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			posts++
		}
		bootstrapReply(w, []any{})
	})
	if _, err := c.MutateBootstrap(context.Background(), q, testValue(t, "fixture-observer"), testValue(t, "fixture-mutator")); err == nil || posts != 0 {
		t.Fatalf("stale state wrote: %v posts=%d", err, posts)
	}
}

func TestBootstrapStagesKeepDNSUntilVerifiedCutover(t *testing.T) {
	const groupID = "22222222-2222-4222-8222-222222222222"
	const appID = "33333333-3333-4333-8333-333333333333"
	const policyID = "44444444-4444-4444-8444-444444444444"
	const connectorID = "55555555-5555-4555-8555-555555555555"
	q := bootstrapTestChange("bootstrap-tunnel")
	oldTarget := "66666666-6666-4666-8666-666666666666.cfargotunnel.com"
	record := map[string]any{"id": q.DNSRecordID, "name": q.Hostname, "type": "CNAME", "content": oldTarget, "proxied": true, "ttl": 1, "comment": "retain me", "tags": []string{"owned"}, "settings": map[string]any{"ipv4_only": false}}
	var tunnel, group, app, policy map[string]any
	config := map[string]any{"ingress": []any{map[string]any{"service": "http_status:404"}}, "warp-routing": map[string]any{"enabled": false}}
	writes, dnsWrites := 0, 0
	serving := false
	c := bootstrapTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if r.Method != http.MethodGet {
			writes++
			if r.Header.Get("Authorization") != "Bearer fixture-mutator" {
				t.Error("wrong write credential")
			}
		} else if r.Header.Get("Authorization") != "Bearer fixture-observer" {
			t.Error("wrong read credential")
		}
		var body map[string]any
		if r.Body != nil && r.Method != http.MethodGet {
			_ = json.NewDecoder(r.Body).Decode(&body)
		}
		switch {
		case strings.HasSuffix(path, "/configurations"):
			if r.Method == http.MethodPut {
				config = body["config"].(map[string]any)
			}
			bootstrapReply(w, map[string]any{"tunnel_id": testUUID, "source": "cloudflare", "config": config})
		case strings.HasSuffix(path, "/connections"):
			rows := []any{}
			if serving {
				rows = append(rows, map[string]any{"id": connectorID, "conns": []any{map[string]any{"id": "connection-a", "client_id": connectorID, "opened_at": "2026-10-28T12:00:00Z", "is_pending_reconnect": false}}})
			}
			bootstrapReply(w, rows)
		case strings.Contains(path, "/dns_records/"):
			if r.Method == http.MethodPut {
				dnsWrites++
				for _, key := range []string{"comment", "tags", "settings"} {
					before, _ := json.Marshal(record[key])
					after, _ := json.Marshal(body[key])
					if string(before) != string(after) {
						t.Errorf("DNS lost %s", key)
					}
				}
				for key, value := range body {
					record[key] = value
				}
			}
			bootstrapReply(w, record)
		case strings.HasSuffix(path, "/policies/"+policyID):
			bootstrapReply(w, policy)
		case strings.HasSuffix(path, "/policies"):
			if r.Method == http.MethodPost {
				policy = body
				policy["id"] = policyID
				bootstrapReply(w, policy)
			} else {
				rows := []any{}
				if policy != nil {
					rows = append(rows, policy)
				}
				bootstrapReply(w, rows)
			}
		case strings.HasSuffix(path, "/access/apps/"+appID):
			bootstrapReply(w, app)
		case strings.HasSuffix(path, "/access/apps"):
			if r.Method == http.MethodPost {
				app = body
				app["id"], app["aud"] = appID, "application-audience"
				bootstrapReply(w, app)
			} else {
				rows := []any{}
				if app != nil {
					rows = append(rows, app)
				}
				bootstrapReply(w, rows)
			}
		case strings.HasSuffix(path, "/access/groups/"+groupID):
			bootstrapReply(w, group)
		case strings.HasSuffix(path, "/access/groups"):
			if r.Method == http.MethodPost {
				group = body
				group["id"] = groupID
				bootstrapReply(w, group)
			} else {
				rows := []any{}
				if group != nil {
					rows = append(rows, group)
				}
				bootstrapReply(w, rows)
			}
		case strings.HasSuffix(path, "/cfd_tunnel/"+testUUID):
			bootstrapReply(w, tunnel)
		case strings.HasSuffix(path, "/cfd_tunnel"):
			if r.Method == http.MethodPost {
				tunnel = body
				tunnel["id"] = testUUID
				tunnel["token"] = "never-serialize-this"
				bootstrapReply(w, tunnel)
			} else {
				rows := []any{}
				if tunnel != nil {
					rows = append(rows, tunnel)
				}
				bootstrapReply(w, rows)
			}
		default:
			t.Errorf("unexpected request %s %s", r.Method, path)
			w.WriteHeader(http.StatusNotFound)
		}
	})
	for i, action := range ingress.BootstrapActions {
		q = bootstrapTestChange(action)
		q.Bootstrap.OriginCAPool = "/etc/vsk-labs/ingress/origin-ca.pem"
		if i > 0 {
			q.TunnelID = testUUID
		}
		if i >= 3 {
			q.AccessAppID, q.AllowedGroupIDs = appID, []string{groupID}
		}
		if i >= 4 {
			q.AccessPolicyID = policyID
		}
		if action == "bootstrap-cutover" {
			q.Connectors[0].ConnectorID = connectorID
			before := writes
			if _, err := c.ObserveBootstrap(context.Background(), q, testValue(t, "fixture-observer")); err == nil || writes != before {
				t.Fatal("absent connector allowed cutover or observation wrote")
			}
			serving = true
		}
		before, err := c.ObserveBootstrap(context.Background(), q, testValue(t, "fixture-observer"))
		if err != nil {
			t.Fatalf("%s observation: %v", action, err)
		}
		q.BeforeDigest = before.Digest
		after, err := c.MutateBootstrap(context.Background(), q, testValue(t, "fixture-observer"), testValue(t, "fixture-mutator"))
		if err != nil || !after.Present || after.ResourceID == "" {
			t.Fatalf("%s effect: %+v %v", action, after, err)
		}
		q.ResourceID = after.ResourceID
		observed, err := c.ObserveBootstrap(context.Background(), q, testValue(t, "fixture-observer"))
		if err != nil || observed.Digest != after.Digest {
			t.Fatalf("%s receipt drift: %+v %v", action, observed, err)
		}
		if action != "bootstrap-cutover" && (record["content"] != oldTarget || dnsWrites != 0) {
			t.Fatalf("%s prematurely published DNS", action)
		}
	}
	if writes != 6 || dnsWrites != 1 || record["content"] != testUUID+".cfargotunnel.com" {
		t.Fatalf("writes=%d DNS writes=%d record=%v", writes, dnsWrites, record)
	}
	encoded, _ := json.Marshal(config)
	if strings.Contains(string(encoded), `"noTLSVerify":true`) || !strings.Contains(string(encoded), `"caPool":"/etc/vsk-labs/ingress/origin-ca.pem"`) {
		t.Fatal("origin trust was bypassed or private CA omitted")
	}
}

func TestBootstrapRejectsInvalidObservationIDBeforeHTTP(t *testing.T) {
	calls := 0
	c := bootstrapTestClient(t, func(http.ResponseWriter, *http.Request) { calls++ })
	q := bootstrapTestChange("bootstrap-tunnel")
	q.ResourceID = "../other-resource"
	if _, err := c.ObserveBootstrap(context.Background(), q, testValue(t, "fixture-observer")); err == nil || calls != 0 {
		t.Fatal("unvalidated observation ID reached provider")
	}
}

func TestBootstrapRetainsKnownCreatedIDWhenObservationFails(t *testing.T) {
	q := bootstrapTestChange("bootstrap-tunnel")
	posts := 0
	c := bootstrapTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			posts++
			bootstrapReply(w, map[string]any{"id": testUUID, "token": "must-not-escape"})
			return
		}
		if strings.HasSuffix(r.URL.Path, "/"+testUUID) {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		bootstrapReply(w, []any{})
	})
	before, _ := c.ObserveBootstrap(context.Background(), q, testValue(t, "fixture-observer"))
	q.BeforeDigest = before.Digest
	partial, err := c.MutateBootstrap(context.Background(), q, testValue(t, "fixture-observer"), testValue(t, "fixture-mutator"))
	encoded, _ := json.Marshal(partial)
	if err == nil || posts != 1 || partial.Present || partial.ResourceID != testUUID || strings.Contains(string(encoded), "must-not-escape") {
		t.Fatalf("known partial effect lost or falsely verified: %+v %v posts=%d", partial, err, posts)
	}
}
