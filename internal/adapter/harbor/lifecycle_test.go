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
	testLifecycleCreatesProtectedRobots(t, false)
}
func TestLifecyclePreservesCreatedIDsWhenSecretUpdateFails(t *testing.T) {
	testLifecycleCreatesProtectedRobots(t, true)
}
func testLifecycleCreatesProtectedRobots(t *testing.T, failPatch bool, artifactRead ...bool) {
	t.Helper()
	retentionID := int64(0)
	var retention map[string]any
	robots := map[string]map[string]any{}
	writes := 0
	secrets := map[string]string{"robot$ci": "Private-ci-secret1", "robot$deploy": "Private-deploy-secret2"}
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
			if robot["level"] != "system" || robot["secret"] != nil {
				t.Error("wrong scoped secret creation")
			}
			id := strconv.Itoa(20 + len(robots))
			secret := "Vendor-generated-secret9"
			delete(robot, "secret")
			robot["name"] = name
			robot["id"], _ = strconv.Atoi(id)
			robot["expires_at"] = time.Now().Add(24 * time.Hour).Unix()
			robots[id] = robot
			out = map[string]any{"id": robot["id"], "name": name, "secret": secret}
			w.WriteHeader(201)
		case r.Method == "PATCH" && strings.HasPrefix(r.URL.Path, "/api/v2.0/robots/"):
			if failPatch {
				w.WriteHeader(500)
				return
			}
			robot := robots[strings.TrimPrefix(r.URL.Path, "/api/v2.0/robots/")]
			var input struct {
				Secret string `json:"secret"`
			}
			if json.NewDecoder(r.Body).Decode(&input) != nil || input.Secret != secrets[robot["name"].(string)] {
				t.Error("wrong scoped secret update")
			}
			out = map[string]string{"secret": ""}
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
	if len(artifactRead) > 0 && artifactRead[0] {
		q.Robots[1].ArtifactRead = true
	}
	out, e := c.ApplyLifecycleWithSecrets(context.Background(), q, "admin", v, func(_ context.Context, r RobotBinding) (*credentialref.Value, error) {
		return credentialref.NewValue([]byte(secrets[r.Name]))
	})
	if failPatch {
		if e == nil || writes != 3 || len(out.Projects) != 1 || out.Projects[0].RetentionID != 9 || len(out.Robots) != 1 || out.Robots[0].ID != 20 {
			t.Fatal("created IDs lost after partial effect", out, e, writes)
		}
		return
	}
	if e != nil || writes != 5 || len(out.Robots) != 2 || out.Projects[0].RetentionID != 9 {
		t.Fatal(out, e, writes)
	}
	raw, _ := json.Marshal(out)
	if strings.Contains(string(raw), "private-") {
		t.Fatal("credential leaked")
	}
	if len(artifactRead) > 0 && artifactRead[0] && (out.ArtifactReadReferenceID != "deploy-ref" || !out.Robots[1].ArtifactRead) {
		t.Fatal("fresh robot missing selected artifact read", out)
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

func TestLifecycleRejectsInvalidStagedSecretBeforeMutation(t *testing.T) {
	writes := 0
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			writes++
		}
		w.WriteHeader(404)
	}))
	defer s.Close()
	c, _ := NewClient(s.URL, s.Client().Transport)
	v, _ := credentialref.NewValue([]byte("fixture-admin"))
	defer v.Close()
	q := LifecycleRequest{Projects: []ProjectBinding{{Name: "project", KeepLast: 5}}, Robots: []RobotBinding{{Name: "robot$ci", ReferenceID: "ci-ref", MaterialVersion: "v1", Push: true, Duration: 7}, {Name: "robot$deploy", ReferenceID: "deploy-ref", MaterialVersion: "v1", Duration: 7}}, Check: func() error { return nil }}
	calls := 0
	_, e := c.ApplyLifecycleWithSecrets(context.Background(), q, "admin", v, func(_ context.Context, r RobotBinding) (*credentialref.Value, error) {
		calls++
		secret := "Valid-protected-secret1"
		if !r.Push {
			secret = "invalid-lowercase"
		}
		return credentialref.NewValue([]byte(secret))
	})
	if e == nil || writes != 0 || calls != 2 {
		t.Fatal("invalid later password allowed provider writes", e, writes, calls)
	}
}

func TestLifecycleReconcilesOnlyMarkedExistingRobot(t *testing.T) {
	writes := 0
	project := ProjectBinding{ID: 11, Name: "project", RetentionID: 9, KeepLast: 5}
	q := LifecycleRequest{Projects: []ProjectBinding{project}, Robots: []RobotBinding{{ID: 7, Name: "robot$ci", ReferenceID: "ci-ref", MaterialVersion: "v1", Push: true, Duration: 7, ReconcileSecret: true}, {ID: 8, Name: "robot$deploy", ReferenceID: "deploy-ref", MaterialVersion: "v1", Duration: 7}}, Check: func() error { return nil }}
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var out any
		switch {
		case r.Method == "GET" && r.URL.Path == "/api/v2.0/projects/project":
			out = map[string]any{"project_id": 11, "name": "project", "metadata": map[string]string{"public": "false", "retention_id": "9"}}
		case r.Method == "GET" && r.URL.Path == "/api/v2.0/retentions/9":
			out = retention(project)
		case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/api/v2.0/robots/"):
			id, e := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/api/v2.0/robots/"))
			if e != nil || id < 7 || id > 8 {
				t.Error("unexpected robot")
			}
			robot := q.Robots[id-7]
			out = map[string]any{"id": id, "name": robot.Name, "level": "system", "disable": false, "expires_at": time.Now().Add(time.Hour).Unix(), "permissions": permissions(q, robot.Push)}
		case r.Method == "PATCH" && r.URL.Path == "/api/v2.0/robots/7":
			writes++
			var body struct {
				Secret string `json:"secret"`
			}
			if json.NewDecoder(r.Body).Decode(&body) != nil || body.Secret != "Protected-secret1" {
				t.Error("wrong reconciled password")
			}
			out = map[string]string{}
		default:
			t.Errorf("unexpected provider mutation %s %s", r.Method, r.URL.Path)
			w.WriteHeader(500)
			return
		}
		json.NewEncoder(w).Encode(out)
	}))
	defer s.Close()
	c, _ := NewClient(s.URL, s.Client().Transport)
	v, _ := credentialref.NewValue([]byte("fixture-admin"))
	defer v.Close()
	calls := 0
	out, e := c.ApplyLifecycleWithSecrets(context.Background(), q, "admin", v, func(_ context.Context, r RobotBinding) (*credentialref.Value, error) {
		calls++
		if r.ID != 7 {
			t.Error("unmarked existing secret read")
		}
		return credentialref.NewValue([]byte("Protected-secret1"))
	})
	if e != nil || writes != 1 || calls != 1 || len(out.Robots) != 2 {
		t.Fatal(out, e, writes, calls)
	}
	raw, _ := json.Marshal(q)
	if strings.Contains(string(raw), "ReconcileSecret") || strings.Contains(string(raw), "reconcileSecret") {
		t.Fatal("transient recovery permission serialized")
	}
}

func TestLifecycleRejectsOmittedExistingRetentionBeforeWrite(t *testing.T) {
	writes := 0
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			writes++
		}
		if r.Method == "GET" && r.URL.Path == "/api/v2.0/projects/project" {
			json.NewEncoder(w).Encode(map[string]any{"project_id": 11, "name": "project", "metadata": map[string]string{"public": "false", "retention_id": "9"}})
			return
		}
		t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		w.WriteHeader(500)
	}))
	defer s.Close()
	c, _ := NewClient(s.URL, s.Client().Transport)
	v, _ := credentialref.NewValue([]byte("fixture-admin"))
	defer v.Close()
	q := LifecycleRequest{Projects: []ProjectBinding{{ID: 11, Name: "project", KeepLast: 5}}, Robots: []RobotBinding{{ID: 7, Name: "robot$ci", ReferenceID: "ci-ref", MaterialVersion: "v1", Push: true, Duration: 7, ReconcileSecret: true}, {Name: "robot$deploy", ReferenceID: "deploy-ref", MaterialVersion: "v1", Duration: 7}}, Check: func() error { return nil }}
	reads := 0
	_, e := c.ApplyLifecycleWithSecrets(context.Background(), q, "admin", v, func(_ context.Context, r RobotBinding) (*credentialref.Value, error) {
		reads++
		return credentialref.NewValue([]byte("Protected-secret1"))
	})
	if e == nil || writes != 0 || reads != 0 {
		t.Fatal("omitted existing retention allowed recovery mutations", e, writes, reads)
	}
}

func TestRobotSecretAcceptsVendorValidSpaces(t *testing.T) {
	if !validRobotSecret([]byte("Valid secret1")) {
		t.Fatal("vendor-valid secret rejected")
	}
	if validRobotSecret([]byte("missing-uppercase1")) {
		t.Fatal("missing required uppercase accepted")
	}
}

// Harbor omits an empty params object when returning an always retention rule.
func TestRetentionComparisonAllowsVendorOmittedEmptyParams(t *testing.T) {
	p := ProjectBinding{ID: 11, Name: "project", RetentionID: 9, KeepLast: 5}
	expected := retention(p)
	observed := retention(p)
	observed.Rules[1].Params = nil
	if !equalRetention(observed, expected) || !equalRetention(expected, observed) {
		t.Fatal("vendor-omitted empty parameters rejected")
	}
	changed := retention(p)
	changed.Rules[0].Params = nil
	if equalRetention(changed, expected) {
		t.Fatal("missing required latestPushedK accepted")
	}
	changed = retention(p)
	changed.Rules[0].Params["latestPushedK"] = 6
	if equalRetention(changed, expected) {
		t.Fatal("changed retention count accepted")
	}
}

func TestLifecycleCreatesSelectedArtifactReadRobotDirectly(t *testing.T) {
	testLifecycleCreatesProtectedRobots(t, false, true)
}
func TestLifecycleAddsArtifactReadWithoutChangingExistingRobot(t *testing.T) {
	testLifecycleArtifactReadTransition(t, "update")
}
func TestLifecycleRejectsArtifactReadNoopOrUnrelatedPermissions(t *testing.T) {
	for _, mode := range []string{"noop", "not-editable", "foreign-permission", "push-selection", "expiry-changed"} {
		t.Run(mode, func(t *testing.T) { testLifecycleArtifactReadTransition(t, mode) })
	}
}
func testLifecycleArtifactReadTransition(t *testing.T, mode string) {
	t.Helper()
	project := ProjectBinding{ID: 11, Name: "project", RetentionID: 9, KeepLast: 5}
	q := LifecycleRequest{Projects: []ProjectBinding{project}, Robots: []RobotBinding{{ID: 7, Name: "robot$push", ReferenceID: "push-ref", Push: true, Duration: 7, MaterialVersion: "v1"}, {ID: 8, Name: "robot$pull", ReferenceID: "pull-ref", Duration: 7, MaterialVersion: "v1", ArtifactRead: true}}, Check: func() error { return nil }}
	if mode == "push-selection" {
		q.Robots[0].ArtifactRead = true
	}
	baseline := []RobotPermission{{Kind: "project", Namespace: "project", Access: []Access{{Resource: "repository", Action: "pull", Effect: "allow"}}}}
	desired := []RobotPermission{{Kind: "project", Namespace: "project", Access: []Access{{Resource: "repository", Action: "pull", Effect: "allow"}, {Resource: "artifact", Action: "read", Effect: "allow"}}}}
	actual := baseline
	if mode == "foreign-permission" {
		actual = []RobotPermission{{Kind: "project", Namespace: "project", Access: []Access{{Resource: "repository", Action: "pull", Effect: "allow"}, {Resource: "repository", Action: "push", Effect: "allow"}}}}
	}
	writes, secretReads := 0, 0
	expires := time.Now().Add(24 * time.Hour).Unix()
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var out any
		switch {
		case r.Method == "GET" && r.URL.Path == "/api/v2.0/projects/project":
			out = map[string]any{"project_id": 11, "name": "project", "metadata": map[string]string{"public": "false", "retention_id": "9"}}
		case r.Method == "GET" && r.URL.Path == "/api/v2.0/retentions/9":
			out = retention(project)
		case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/api/v2.0/robots/"):
			id, e := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/api/v2.0/robots/"))
			if e != nil || id < 7 || id > 8 {
				t.Fatal("unexpected robot")
			}
			robot := q.Robots[id-7]
			perms := []RobotPermission{{Kind: "project", Namespace: "project", Access: []Access{{Resource: "repository", Action: "pull", Effect: "allow"}, {Resource: "repository", Action: "push", Effect: "allow"}}}}
			if id == 8 {
				perms = actual
			}
			out = map[string]any{"id": id, "name": robot.Name, "level": "system", "description": "retained-description", "disable": false, "editable": mode != "not-editable", "duration": 7, "expires_at": expires, "permissions": perms}
		case r.Method == "PUT" && r.URL.Path == "/api/v2.0/robots/8":
			writes++
			var body map[string]json.RawMessage
			if json.NewDecoder(r.Body).Decode(&body) != nil || len(body) != 5 {
				t.Error("permission update must preserve only required metadata and omit duration/secret")
			}
			var name, level, description string
			var disabled bool
			var perms []RobotPermission
			json.Unmarshal(body["name"], &name)
			json.Unmarshal(body["level"], &level)
			json.Unmarshal(body["description"], &description)
			json.Unmarshal(body["disable"], &disabled)
			json.Unmarshal(body["permissions"], &perms)
			if name != "robot$pull" || level != "system" || description != "retained-description" || disabled || !permissionEqual(perms, desired) {
				t.Error("permission update changed unrelated robot settings")
			}
			if mode != "noop" {
				actual = desired
			}
			if mode == "expiry-changed" {
				expires++
			}
			return // Harbor PUT returns an empty200 response.
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(500)
			return
		}
		json.NewEncoder(w).Encode(out)
	}))
	defer s.Close()
	c, _ := NewClient(s.URL, s.Client().Transport)
	v, _ := credentialref.NewValue([]byte("fixture-admin"))
	defer v.Close()
	var beforeJSON []byte
	if mode == "update" {
		before, e := c.ObserveLifecycle(context.Background(), q, "admin", v)
		if e != nil || before.ArtifactReadReferenceID != "" || before.Robots[1].ArtifactRead {
			t.Fatal("old permission observation not sealed accurately", before, e)
		}
		beforeJSON, _ = json.Marshal(before)
	}
	out, e := c.ApplyLifecycleWithSecrets(context.Background(), q, "admin", v, func(context.Context, RobotBinding) (*credentialref.Value, error) {
		secretReads++
		return credentialref.NewValue([]byte("Must-not-be-read1"))
	})
	if secretReads != 0 {
		t.Fatal("permission-only transition borrowed a robot password")
	}
	if mode == "update" {
		afterJSON, _ := json.Marshal(out)
		if string(beforeJSON) == string(afterJSON) {
			t.Fatal("old and new permission states have identical canonical snapshot")
		}
		if e != nil || writes != 1 || len(out.Robots) != 2 || !out.Robots[1].ArtifactRead || out.ArtifactReadReferenceID != "pull-ref" {
			t.Fatal("artifact read transition not verified", out, e, writes)
		}
	} else {
		expectedWrites := 0
		if mode == "noop" || mode == "expiry-changed" {
			expectedWrites = 1
		}
		if e == nil || writes != expectedWrites {
			t.Fatal("invalid artifact read transition accepted", out, e, writes)
		}
	}
}
