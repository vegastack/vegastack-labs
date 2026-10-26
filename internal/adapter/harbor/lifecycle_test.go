package harbor

import (
	"context"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestLifecycleCreatesTwoSystemRobotsFromProtectedSecrets(t *testing.T) {
	retentionID := int64(0)
	var retention map[string]any
	robots := map[string]map[string]any{}
	writes := 0
	secrets := map[string]string{"robot$ci": "private-ci-secret", "robot$deploy": "private-deploy-secret"}
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			writes++
		}
		u, p, ok := r.BasicAuth()
		if !ok || u != "admin" || p != "fixture-admin" {
			t.Error("admin credential mismatch")
		}
		var out any
		switch {
		case r.Method == "GET" && r.URL.Path == "/api/v2.0/projects/project":
			out = map[string]any{"project_id": 11, "name": "project", "metadata": map[string]string{"public": "false", "retention_id": strconv.FormatInt(retentionID, 10)}}
		case r.Method == "POST" && r.URL.Path == "/api/v2.0/retentions":
			if json.NewDecoder(r.Body).Decode(&retention) != nil {
				t.Error("bad retention")
			}
			retentionID = 9
			retention["id"] = 9
			w.WriteHeader(201)
			return
		case r.Method == "GET" && r.URL.Path == "/api/v2.0/retentions/9":
			out = retention
		case r.Method == "POST" && r.URL.Path == "/api/v2.0/robots":
			var robot map[string]any
			if json.NewDecoder(r.Body).Decode(&robot) != nil {
				t.Error("bad robot")
			}
			name := "robot$" + robot["name"].(string)
			if robot["level"] != "system" || robot["secret"] != secrets[name] {
				t.Error("wrong scoped secret creation")
			}
			id := strconv.Itoa(20 + len(robots))
			secret := robot["secret"]
			delete(robot, "secret")
			robot["name"] = name
			robot["id"], _ = strconv.Atoi(id)
			robot["expires_at"] = time.Now().Add(24 * time.Hour).Unix()
			robots[id] = robot
			out = map[string]any{"id": robot["id"], "name": name, "secret": secret}
			w.WriteHeader(201)
		case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/api/v2.0/robots/"):
			out = robots[strings.TrimPrefix(r.URL.Path, "/api/v2.0/robots/")]
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(404)
			return
		}
		json.NewEncoder(w).Encode(out)
	}))
	defer s.Close()
	c, _ := NewClient(s.URL, s.Client().Transport)
	v, _ := credentialref.NewValue([]byte("fixture-admin"))
	defer v.Close()
	q := LifecycleRequest{Projects: []ProjectBinding{{ID: 11, Name: "project", KeepLast: 20}}, Robots: []RobotBinding{{Name: "robot$ci", ReferenceID: "ci-ref", MaterialVersion: "v1", Push: true, Duration: 365}, {Name: "robot$deploy", ReferenceID: "deploy-ref", MaterialVersion: "v1", Duration: 365}}, Check: func() error { return nil }}
	out, e := c.ApplyLifecycleWithSecrets(context.Background(), q, "admin", v, func(_ context.Context, r RobotBinding) (*credentialref.Value, error) {
		return credentialref.NewValue([]byte(secrets[r.Name]))
	})
	if e != nil || writes != 3 || len(out.Robots) != 2 || out.Projects[0].RetentionID != 9 {
		t.Fatal(out, e, writes)
	}
	raw, _ := json.Marshal(out)
	if strings.Contains(string(raw), "private-") {
		t.Fatal("credential leaked")
	}
	if out.Robots[0].Push == out.Robots[1].Push {
		t.Fatal("two robot separation lost")
	}
}
func TestLifecycleRejectsRobotPrivilegeExpansionBeforeWrite(t *testing.T) {
	writes := 0
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			writes++
		}
		if strings.Contains(r.URL.Path, "projects") {
			json.NewEncoder(w).Encode(map[string]any{"project_id": 11, "name": "project", "metadata": map[string]string{"public": "false"}})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"id": 7, "name": "robot$ci", "level": "system", "expires_at": time.Now().Add(time.Hour).Unix(), "permissions": []any{map[string]any{"kind": "project", "namespace": "foreign", "access": []any{map[string]any{"resource": "repository", "action": "pull", "effect": "allow"}}}}})
	}))
	defer s.Close()
	c, _ := NewClient(s.URL, s.Client().Transport)
	v, _ := credentialref.NewValue([]byte("fixture-admin"))
	defer v.Close()
	_, e := c.ApplyLifecycle(context.Background(), LifecycleRequest{Projects: []ProjectBinding{{ID: 11, Name: "project", KeepLast: 5}}, Robots: []RobotBinding{{ID: 7, Name: "robot$ci", ReferenceID: "ci-ref", MaterialVersion: "v1", Push: true, Duration: 30}, {ID: 8, Name: "robot$deploy", ReferenceID: "pull-ref", MaterialVersion: "v1", Duration: 30}}, Check: func() error { return nil }}, "admin", v, nil)
	if e == nil || writes != 0 {
		t.Fatal("foreign namespace mutation", e, writes)
	}
}
