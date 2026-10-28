package cloudflare

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIngressPilotAudienceUsesExactExistingApplicationRead(t *testing.T) {
	q := ingressTestChange()
	domain, audience := q.Hostname, "actual-app-audience"
	calls := 0
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != http.MethodGet || r.URL.Path != "/accounts/"+q.AccountID+"/access/apps/"+q.AccessAppID || r.Header.Get("Authorization") != "Bearer fixture-observer" {
			t.Error("pilot audience read escaped scope")
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"success": true, "result": map[string]any{"id": q.AccessAppID, "domain": domain, "aud": audience}})
	}))
	defer provider.Close()
	client := &SDKClient{transport: provider.Client().Transport, base: provider.URL + "/"}
	value := testValue(t, "fixture-observer")
	defer value.Close()
	if got, err := client.ObservePilotAudience(context.Background(), q, value); err != nil || got != audience {
		t.Fatalf("audience observation: %q %v", got, err)
	}
	domain = "unrelated.example"
	if _, err := client.ObservePilotAudience(context.Background(), q, value); err == nil {
		t.Fatal("foreign app accepted")
	}
	domain, audience = q.Hostname, ""
	if _, err := client.ObservePilotAudience(context.Background(), q, value); err == nil {
		t.Fatal("unknown audience accepted")
	}
	if calls != 3 {
		t.Fatalf("unexpected provider calls: %d", calls)
	}
}
