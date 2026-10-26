package coolify

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func deploymentFixture(t *testing.T, mode string) (*Client, *ImageDeploymentRequest, *[]string) {
	t.Helper()
	calls := []string{}
	q := &ImageDeploymentRequest{Target: target(), DestinationUUID: "destination-one", ServerUUID: "server-one", ServerID: 5, Repository: "registry.example/app", Digest: "sha256:" + strings.Repeat("a", 64), Check: func() error { return nil }}
	fs := fixtures()
	fs["/api/v1/applications/app-one"] = `{"uuid":"app-one","environment_id":3,"destination_id":4,"destination_type":"App\\Models\\StandaloneDocker","build_pack":"dockerimage","additional_servers_count":0,"additional_networks_count":0}`
	if mode == "counts" {
		fs["/api/v1/applications/app-one"] = strings.ReplaceAll(fs["/api/v1/applications/app-one"], `"additional_networks_count":0`, `"additional_networks_count":1`)
	}
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.RequestURI())
		if r.Header.Get("Authorization") != "Bearer "+secret {
			t.Error("credential header")
		}
		if r.Method == http.MethodPatch {
			b, _ := io.ReadAll(r.Body)
			var fields map[string]string
			if json.Unmarshal(b, &fields) != nil || len(fields) != 2 || fields["docker_registry_image_name"] != q.Repository || fields["docker_registry_image_tag"] != "sha256-"+strings.Repeat("a", 64) {
				t.Errorf("patch %s", b)
			}
			fmt.Fprint(w, `{"uuid":"app-one","secret":"hidden"}`)
			return
		}
		if r.Method == http.MethodPost {
			if mode == "post-fail" {
				w.WriteHeader(502)
				fmt.Fprint(w, secret)
				return
			}
			b, _ := io.ReadAll(r.Body)
			if string(b) != `{"uuid":"app-one"}` {
				t.Errorf("post %s", b)
			}
			fmt.Fprint(w, `{"deployments":[{"resource_uuid":"app-one","deployment_uuid":"deployment-one","message":"hidden"}]}`)
			return
		}
		switch r.URL.Path {
		case "/api/v1/applications/app-one/destinations":
			if mode == "fanout" {
				fmt.Fprint(w, `[{"uuid":"destination-one","server_uuid":"server-one","server_id":5,"is_primary":true},{"uuid":"protected","server_uuid":"vsk-node-04","server_id":44,"is_primary":false}]`)
				return
			}
			fmt.Fprint(w, `[{"uuid":"destination-one","server_uuid":"server-one","server_id":5,"is_primary":true}]`)
		case "/api/v1/deployments/applications/app-one":
			fmt.Fprint(w, `{"deployments":[{"deployment_uuid":"deployment-one"}],"count":1}`)
		case "/api/v1/deployments/deployment-one":
			if mode == "lost" {
				w.WriteHeader(404)
				return
			}
			fmt.Fprint(w, `{"deployment_uuid":"deployment-one","status":"finished","server_id":5,"destination_id":"4","logs":"`+secret+`","configuration_snapshot":{"secret":"hidden"}}`)
		default:
			body, ok := fs[r.URL.Path]
			if !ok {
				t.Errorf("unexpected %s", r.URL)
				w.WriteHeader(404)
				return
			}
			fmt.Fprint(w, body)
		}
	}))
	t.Cleanup(s.Close)
	c, e := NewClient(s.URL+"/api/v1", s.Client().Transport)
	if e != nil {
		t.Fatal(e)
	}
	return c, q, &calls
}
func TestDeployImagePinnedDigestProtocol(t *testing.T) {
	c, q, calls := deploymentFixture(t, "")
	v := credential(t)
	checks := 0
	q.Check = func() error { checks++; return nil }
	got, e := c.DeployImage(context.Background(), *q, v)
	if e != nil {
		t.Fatal(e)
	}
	if got.Stage != "queued" || got.ProviderStatus != "finished" || got.RuntimeDigestVerified || got.DeploymentUUID != "deployment-one" {
		t.Fatalf("%+v", got)
	}
	if checks < len(*calls) {
		t.Fatal("missing request check")
	}
	b, _ := json.Marshal(got)
	if strings.Contains(string(b), secret) || strings.Contains(string(b), "hidden") {
		t.Fatal("unsanitized receipt")
	}
	if string(v.Bytes()) != secret {
		t.Fatal("borrowed credential mutated")
	}
	observed, e := c.ObserveDeployment(context.Background(), q.Target.ApplicationUUID, got.DeploymentUUID, v)
	if e != nil || observed.ProviderStatus != "finished" {
		t.Fatalf("%+v %v", observed, e)
	}
}
func TestDeployImageRejectsAdditionalTargetsBeforeWrites(t *testing.T) {
	for _, mode := range []string{"counts", "fanout"} {
		t.Run(mode, func(t *testing.T) {
			c, q, calls := deploymentFixture(t, mode)
			_, e := c.DeployImage(context.Background(), *q, credential(t))
			if e == nil {
				t.Fatal("accepted additional targets")
			}
			for _, call := range *calls {
				if !strings.HasPrefix(call, "GET ") {
					t.Fatalf("write %s", call)
				}
			}
		})
	}
}
func TestDeployImagePartialEffectsNeverRetry(t *testing.T) {
	for _, tc := range []struct{ mode, stage string }{{"post-fail", "deploy_attempted"}, {"lost", "deploy_attempted"}} {
		t.Run(tc.mode, func(t *testing.T) {
			c, q, calls := deploymentFixture(t, tc.mode)
			got, e := c.DeployImage(context.Background(), *q, credential(t))
			if e == nil || got.Stage != tc.stage {
				t.Fatalf("%+v %v", got, e)
			}
			patch, post := 0, 0
			for _, call := range *calls {
				if strings.HasPrefix(call, "PATCH ") {
					patch++
				}
				if strings.HasPrefix(call, "POST ") {
					post++
				}
			}
			if patch != 1 || post != 1 {
				t.Fatal(*calls)
			}
			if strings.Contains(e.Error(), secret) {
				t.Fatal("provider secret exposed")
			}
		})
	}
}
func TestDeployImageRejectsMissingCheckAndInvalidDigest(t *testing.T) {
	c, q, calls := deploymentFixture(t, "")
	q.Check = nil
	if _, e := c.DeployImage(context.Background(), *q, credential(t)); e == nil {
		t.Fatal("missing policy check")
	}
	q.Check = func() error { return nil }
	q.Digest = "latest"
	if _, e := c.DeployImage(context.Background(), *q, credential(t)); e == nil {
		t.Fatal("mutable image")
	}
	if len(*calls) != 0 {
		t.Fatal(*calls)
	}
}
