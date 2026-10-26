package coolify

import (
	"context"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestResourcesNeverAdoptForeignTeam(t *testing.T) {
	writes := 0
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			writes++
		}
		json.NewEncoder(w).Encode(map[string]any{"id": 99})
	}))
	defer s.Close()
	c, _ := NewClient(s.URL, s.Client().Transport)
	v, _ := credentialref.NewValue([]byte("fixture-token"))
	defer v.Close()
	_, e := c.ApplyResources(context.Background(), ResourceRequest{TeamID: 1, ProjectName: "project", Environment: "production", Check: func() error { return nil }}, v)
	if e == nil || writes != 0 {
		t.Fatalf("foreign team accepted or mutated %d", writes)
	}
}

func TestResourcesCreateThenVerifyExactOwnedIDs(t *testing.T) {
	project, environment, application := false, false, false
	writes := 0
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer fixture-token" {
			t.Error("missing credential")
		}
		if r.Method != "GET" {
			writes++
		}
		var out any
		switch r.Method + " " + r.URL.Path {
		case "GET /team":
			out = map[string]any{"id": 1}
		case "GET /servers/server-a":
			out = map[string]any{"id": 7, "uuid": "server-a", "ip": "192.0.2.10"}
		case "GET /servers/server-a/destinations":
			out = []any{map[string]any{"uuid": "destination-a", "server_id": 7}}
		case "GET /projects":
			out = []any{}
		case "POST /projects":
			project = true
			out = map[string]any{"uuid": "project-a"}
			w.WriteHeader(201)
		case "GET /projects/project-a":
			if !project {
				t.Error("project GET before actual creation")
			}
			out = map[string]any{"id": 2, "uuid": "project-a", "name": "project", "team_id": 1}
		case "GET /projects/project-a/environments":
			out = []any{}
			if environment {
				out = []any{map[string]any{"id": 3, "name": "production", "project_id": 2}}
			}
		case "POST /projects/project-a/environments":
			environment = true
			out = map[string]any{"uuid": "env-a"}
			w.WriteHeader(201)
		case "POST /applications/dockerimage":
			application = true
			var body map[string]any
			if json.NewDecoder(r.Body).Decode(&body) != nil || body["instant_deploy"] != false || body["server_uuid"] != "server-a" {
				t.Error("unsealed create")
			}
			out = map[string]any{"uuid": "app-a"}
			w.WriteHeader(201)
		case "GET /applications/app-a":
			if !application {
				t.Error("not created")
			}
			out = map[string]any{"uuid": "app-a", "environment_id": 3}
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(404)
			return
		}
		json.NewEncoder(w).Encode(out)
	}))
	defer s.Close()
	c, _ := NewClient(s.URL, s.Client().Transport)
	v, _ := credentialref.NewValue([]byte("fixture-token"))
	defer v.Close()
	out, e := c.ApplyResources(context.Background(), ResourceRequest{TeamID: 1, ProjectName: "project", Environment: "production", ServerID: 7, ServerAddress: "192.0.2.10", ServerUUID: "server-a", DestinationUUID: "destination-a", ApplicationName: "app", Image: "registry.example/project/app", ImageTag: "v1", Ports: "8080", Check: func() error { return nil }}, v)
	if e != nil || writes != 3 || out.ProjectUUID != "project-a" || out.EnvironmentID != 3 || out.ApplicationUUID != "app-a" {
		t.Fatal(out, e, writes)
	}
}

func TestResourceCreationNeverPublishesCredentialAsExternalID(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "GET /team":
			json.NewEncoder(w).Encode(map[string]any{"id": 1})
		case "GET /projects":
			json.NewEncoder(w).Encode([]any{})
		case "POST /projects":
			w.WriteHeader(201)
			json.NewEncoder(w).Encode(map[string]any{"uuid": "fixture-token"})
		default:
			t.Error("untrusted external ID followed")
			w.WriteHeader(404)
		}
	}))
	defer s.Close()
	c, _ := NewClient(s.URL, s.Client().Transport)
	v, _ := credentialref.NewValue([]byte("fixture-token"))
	defer v.Close()
	out, e := c.ApplyResources(context.Background(), ResourceRequest{TeamID: 1, ProjectName: "project", Environment: "production", Check: func() error { return nil }}, v)
	if e == nil || out.ProjectUUID != "" {
		t.Fatal("credential reached ownership result", out, e)
	}
}
