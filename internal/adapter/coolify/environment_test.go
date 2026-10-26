package coolify

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEnvironmentSecretsUseFixedPatchAndNeverReturnResponseValues(t *testing.T) {
	value, e := credentialref.NewValue([]byte("private-application-secret"))
	if e != nil {
		t.Fatal(e)
	}
	defer value.Close()
	calls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != "PATCH" || r.URL.Path != "/api/v1/applications/app-one/envs" {
			t.Errorf("wrong route %s %s", r.Method, r.URL)
		}
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		if json.Unmarshal(raw, &body) != nil || body["key"] != "APP_KEY" || body["value"] != string(value.Bytes()) || body["is_literal"] != true || body["is_shown_once"] != true {
			t.Error("wrong finite environment payload")
		}
		w.WriteHeader(201)
		fmt.Fprint(w, `{"value":"private-application-secret"}`)
	}))
	defer server.Close()
	client, e := NewClient(server.URL+"/api/v1", server.Client().Transport)
	if e != nil {
		t.Fatal(e)
	}
	checks := 0
	e = client.applyEnvironment(context.Background(), "app-one", []EnvironmentValue{{Name: "APP_KEY", Value: value}}, credential(t), func() error { checks++; return nil })
	if e != nil || calls != 1 || checks != 2 {
		t.Fatal(e, calls, checks)
	}
	e = client.applyEnvironment(context.Background(), "app-one", []EnvironmentValue{{Name: "APP_KEY; touch /tmp/x", Value: value}}, credential(t), func() error { return nil })
	if e == nil || calls != 1 || strings.Contains(e.Error(), string(value.Bytes())) {
		t.Fatal("unsafe or secret-bearing environment failure")
	}
}
