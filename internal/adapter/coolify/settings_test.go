package coolify

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func settingsFixture() generated.ServiceConfiguration {
	return generated.ServiceConfiguration{Schema: "vegastack-labs.dev/service-configuration", SchemaVersion: "1.0.0", EnvironmentClass: "development", CPUQuotaPercent: 125, MemoryBytes: 268435456, Port: 8080, Exposure: "private", HealthPath: "/ready", HealthExpectedStatus: 200, HealthIntervalSeconds: 10, HealthTimeoutSeconds: 2, HealthRetries: 3, DataClass: "stateless", Migration: "none", Rollback: "previous-artifact", SecretReferenceIDs: []string{}}
}
func TestServiceSettingsMustMatchBeforeDeployment(t *testing.T) {
	for _, drift := range []bool{false, true} {
		t.Run(fmt.Sprint(drift), func(t *testing.T) {
			expected, e := Settings(settingsFixture())
			if e != nil {
				t.Fatal(e)
			}
			patched := false
			deploys := 0
			checks := 0
			fs := fixtures()
			fs["/api/v1/applications/app-one"] = `{"uuid":"app-one","environment_id":3,"destination_id":4,"destination_type":"App\\Models\\StandaloneDocker","build_pack":"dockerimage","additional_servers_count":0,"additional_networks_count":0}`
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPatch {
					raw, _ := io.ReadAll(r.Body)
					var got map[string]any
					if json.Unmarshal(raw, &got) != nil || got["limits_cpus"] != "1.25" || got["health_check_path"] != "/ready" || got["limits_memory"] != "268435456" {
						t.Errorf("wrong settings %s", raw)
					}
					patched = true
					fmt.Fprint(w, `{"uuid":"app-one"}`)
					return
				}
				if r.Method == http.MethodPost {
					deploys++
					fmt.Fprint(w, `{"deployments":[{"resource_uuid":"app-one","deployment_uuid":"deployment-one"}]}`)
					return
				}
				switch r.URL.Path {
				case "/api/v1/applications/app-one":
					if patched {
						got := expected
						if drift {
							got.HealthPath = "/wrong"
						}
						_ = json.NewEncoder(w).Encode(got)
					} else {
						fmt.Fprint(w, fs[r.URL.Path])
					}
				case "/api/v1/applications/app-one/destinations":
					fmt.Fprint(w, `[{"uuid":"destination-one","server_uuid":"server-one","server_id":5,"is_primary":true}]`)
				case "/api/v1/deployments/applications/app-one":
					fmt.Fprint(w, `{"deployments":[{"deployment_uuid":"deployment-one"}],"count":1}`)
				case "/api/v1/deployments/deployment-one":
					fmt.Fprint(w, `{"deployment_uuid":"deployment-one","status":"finished","server_id":5,"destination_id":"4"}`)
				default:
					body, ok := fs[r.URL.Path]
					if !ok {
						t.Errorf("unexpected %s", r.URL)
						w.WriteHeader(404)
					}
					fmt.Fprint(w, body)
				}
			}))
			defer server.Close()
			client, e := NewClient(server.URL+"/api/v1", server.Client().Transport)
			if e != nil {
				t.Fatal(e)
			}
			q := ImageDeploymentRequest{Target: target(), DestinationUUID: "destination-one", ServerUUID: "server-one", ServerID: 5, Repository: "registry.example/app", Digest: "sha256:" + strings.Repeat("a", 64), Settings: &expected, Check: func() error { checks++; return nil }}
			out, e := client.DeployImage(context.Background(), q, credential(t))
			if drift {
				if e == nil || deploys != 0 || out.Stage != "patch_attempted" {
					t.Fatalf("settings drift deployed %+v %v deploys%d", out, e, deploys)
				}
			} else if e != nil || deploys != 1 || checks < 10 {
				t.Fatalf("settings not verified %+v %v %d %d", out, e, deploys, checks)
			}
		})
	}
}
