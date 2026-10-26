package coolify

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

const secret = "fixture-private-token"

func credential(t *testing.T) *credentialref.Value {
	t.Helper()
	v, e := credentialref.NewValue([]byte(secret))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(v.Close)
	return v
}
func target() ApplicationTarget {
	return ApplicationTarget{TeamID: 1, ProjectID: 2, ProjectUUID: "project-one", EnvironmentID: 3, Environment: "production", ApplicationUUID: "app-one", DestinationID: 4, DestinationType: "App\\Models\\StandaloneDocker"}
}
func fixtures() map[string]string {
	return map[string]string{
		"/api/v1/team":                            `{"id":1,"name":"private","members":[{"token":"hidden"}]}`,
		"/api/v1/projects/project-one":            `{"id":2,"uuid":"project-one"}`,
		"/api/v1/projects/project-one/production": `{"id":3,"name":"production","project_id":2}`,
		"/api/v1/applications/app-one":            `{"uuid":"app-one","environment_id":3,"destination_id":4,"destination_type":"App\\Models\\StandaloneDocker","docker_registry_image_name":"registry.example/app","docker_registry_image_tag":"v1","status":"running:healthy","http_basic_auth_password":"hidden"}`,
		"/api/v1/servers/server-one":              `{"id":5,"uuid":"server-one","ip":"private","validation_logs":"hidden","settings":{"is_reachable":true}}`,
	}
}
func fixtureClient(t *testing.T, responses map[string]string) (*Client, *httptest.Server, *[]string) {
	t.Helper()
	var paths []string
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if r.Method != "GET" || r.Header.Get("Authorization") != "Bearer "+secret || r.URL.RawQuery != "" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		body, ok := responses[r.URL.Path]
		if !ok {
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(404)
			return
		}
		fmt.Fprint(w, body)
	}))
	t.Cleanup(s.Close)
	c, e := NewClient(s.URL+"/api/v1", s.Client().Transport)
	if e != nil {
		t.Fatal(e)
	}
	return c, s, &paths
}
func TestObserveApplicationPinnedPathsIdentityAndSanitizedConfiguration(t *testing.T) {
	c, _, paths := fixtureClient(t, fixtures())
	v := credential(t)
	got, e := c.ObserveApplication(context.Background(), target(), v)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Join(*paths, ",") != "/api/v1/team,/api/v1/projects/project-one,/api/v1/projects/project-one/production,/api/v1/applications/app-one" {
		t.Fatal(*paths)
	}
	if got.ConfiguredImageName != "registry.example/app" || got.ConfiguredImageTag != "v1" || got.ProviderStatus != "running:healthy" || got.ServerRelation != "unknown" {
		t.Fatalf("unexpected snapshot %+v", got)
	}
	b, _ := json.Marshal(got)
	for _, s := range []string{"hidden", "private", secret, "digest", "healthy\":true"} {
		if strings.Contains(string(b), s) {
			t.Fatalf("unsafe snapshot %s", b)
		}
	}
	if string(v.Bytes()) != secret {
		t.Fatal("borrowed credential changed")
	}
}
func TestObserveApplicationRejectsWrongRelationships(t *testing.T) {
	for _, tc := range []struct{ name, path, body string }{
		{"team", "/api/v1/team", `{"id":9}`}, {"project", "/api/v1/projects/project-one", `{"id":9,"uuid":"project-one"}`}, {"project-uuid", "/api/v1/projects/project-one", `{"id":2,"uuid":"another"}`}, {"environment", "/api/v1/projects/project-one/production", `{"id":9,"project_id":2,"name":"production"}`}, {"environment-project", "/api/v1/projects/project-one/production", `{"id":3,"project_id":9,"name":"production"}`}, {"application", "/api/v1/applications/app-one", `{"uuid":"other"}`}, {"destination", "/api/v1/applications/app-one", `{"uuid":"app-one","environment_id":3,"destination_id":9,"destination_type":"App\\Models\\StandaloneDocker"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := fixtures()
			f[tc.path] = tc.body
			c, _, _ := fixtureClient(t, f)
			got, e := c.ObserveApplication(context.Background(), target(), credential(t))
			if e == nil || got != (ApplicationSnapshot{}) {
				t.Fatalf("accepted mismatch: %+v %v", got, e)
			}
		})
	}
}
func TestObserveServerDoesNotValidateOrInventHealth(t *testing.T) {
	c, _, paths := fixtureClient(t, fixtures())
	got, e := c.ObserveServer(context.Background(), ServerTarget{TeamID: 1, ServerID: 5, ServerUUID: "server-one"}, credential(t))
	if e != nil || got.ProviderStatus != "unknown" || len(*paths) != 2 {
		t.Fatalf("%+v %v %v", got, e, *paths)
	}
}
func TestRejectsUnsafeInputsBeforeRequests(t *testing.T) {
	for _, u := range []string{"http://example.com", "https://user:pass@example.com", "https://example.com?x=1", "https://example.com#x", "https://example.com/%2f"} {
		if _, e := NewClient(u, nil); e == nil {
			t.Fatalf("accepted %s", u)
		}
	}
	c, _, paths := fixtureClient(t, fixtures())
	for _, s := range []string{"../other", "x/y", "x?y", "x%2fy", ""} {
		q := target()
		q.ApplicationUUID = s
		if _, e := c.ObserveApplication(context.Background(), q, credential(t)); e == nil {
			t.Fatal("accepted identifier")
		}
	}
	v, _ := credentialref.NewValue([]byte("bad\r\ntoken"))
	defer v.Close()
	if _, e := c.ObserveApplication(context.Background(), target(), v); e == nil {
		t.Fatal("accepted credential")
	}
	if len(*paths) != 0 {
		t.Fatal(*paths)
	}
}
func TestRejectsMalformedDuplicateAndOversizedJSON(t *testing.T) {
	for _, body := range []string{`{"id":1`, `{"id":1,"id":1}`, `{"id":1,"extra":{"x":1,"x":2}}`, `{"id":1} {}`, `null`, strings.Repeat(" ", maxBody+1)} {
		t.Run(fmt.Sprint(len(body), body[:min(len(body), 16)]), func(t *testing.T) {
			f := fixtures()
			f["/api/v1/team"] = body
			c, _, _ := fixtureClient(t, f)
			if _, e := c.ObserveApplication(context.Background(), target(), credential(t)); e == nil {
				t.Fatal("accepted invalid JSON")
			}
		})
	}
}
func TestProviderErrorsRedirectTLSAndCancellationAreSanitized(t *testing.T) {
	for _, status := range []int{301, 401, 403, 404, 429, 500} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			var requests int
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				w.Header().Set("Location", "/leak")
				w.WriteHeader(status)
				fmt.Fprint(w, secret)
			}))
			defer s.Close()
			c, _ := NewClient(s.URL, s.Client().Transport)
			_, e := c.ObserveServer(context.Background(), ServerTarget{TeamID: 1, ServerID: 5, ServerUUID: "server-one"}, credential(t))
			if e == nil || strings.Contains(e.Error(), secret) || strings.Contains(e.Error(), s.URL) || requests != 1 {
				t.Fatalf("%v requests=%d", e, requests)
			}
			expected := map[int]string{301: generated.ErrorCodeDependencyUnavailable, 401: generated.ErrorCodeAuthenticationRequired, 403: generated.ErrorCodeAuthorizationDenied, 404: generated.ErrorCodeResourceNotFound, 429: generated.ErrorCodeRateLimited, 500: generated.ErrorCodeDependencyUnavailable}[status]
			stable, ok := failure.As(e)
			if !ok || stable.Code != expected || stable.Target != "coolify-observation" || stable.Retryable {
				t.Fatalf("unexpected stable error: %+v", e)
			}
		})
	}
	c, s, _ := fixtureClient(t, fixtures())
	untrusted, _ := NewClient(s.URL, nil)
	if _, e := untrusted.ObserveApplication(context.Background(), target(), credential(t)); e == nil || strings.Contains(e.Error(), s.URL) {
		t.Fatalf("TLS error %v", e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := c.ObserveApplication(ctx, target(), credential(t)); e == nil {
		t.Fatal("ignored cancellation")
	}
}
func TestRequestDeadlineBoundsSlowProvider(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(time.Second):
		}
	}))
	defer s.Close()
	c, _ := NewClient(s.URL, s.Client().Transport)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, e := c.ObserveApplication(ctx, target(), credential(t)); e == nil {
		t.Fatal("ignored timeout")
	}
}

func TestObserveApplicationRejectsEnvironmentAndDestinationTypeMismatch(t *testing.T) {
	for _, field := range []string{"environment_id", "destination_type"} {
		t.Run(field, func(t *testing.T) {
			f := fixtures()
			var app map[string]any
			if e := json.Unmarshal([]byte(f["/api/v1/applications/app-one"]), &app); e != nil {
				t.Fatal(e)
			}
			if field == "environment_id" {
				app[field] = 99
			} else {
				app[field] = "another-destination"
			}
			b, _ := json.Marshal(app)
			f["/api/v1/applications/app-one"] = string(b)
			c, _, _ := fixtureClient(t, f)
			got, e := c.ObserveApplication(context.Background(), target(), credential(t))
			if e != ErrIdentity || got != (ApplicationSnapshot{}) {
				t.Fatalf("accepted %s: %+v %v", field, got, e)
			}
		})
	}
}
func TestObserveServerRejectsWrongUUIDAndID(t *testing.T) {
	for _, body := range []string{`{"id":5,"uuid":"another"}`, `{"id":99,"uuid":"server-one"}`} {
		f := fixtures()
		f["/api/v1/servers/server-one"] = body
		c, _, _ := fixtureClient(t, f)
		got, e := c.ObserveServer(context.Background(), ServerTarget{TeamID: 1, ServerID: 5, ServerUUID: "server-one"}, credential(t))
		if e != ErrIdentity || got != (ServerSnapshot{}) {
			t.Fatalf("accepted server mismatch: %+v %v", got, e)
		}
	}
}
func TestSensitiveTextInWhitelistedFieldsIsOmitted(t *testing.T) {
	f := fixtures()
	f["/api/v1/applications/app-one"] = `{"uuid":"app-one","environment_id":3,"destination_id":4,"destination_type":"App\\Models\\StandaloneDocker","docker_registry_image_name":"https://user:password@example.com/app?token=hidden","docker_registry_image_tag":"fixture-private-token","status":"secret-provider-message"}`
	c, _, _ := fixtureClient(t, f)
	got, e := c.ObserveApplication(context.Background(), target(), credential(t))
	if e != nil || got.ConfiguredImageName != "" || got.ConfiguredImageTag != "" || got.ProviderStatus != "unknown" {
		t.Fatalf("unsafe snapshot %+v %v", got, e)
	}
}
func TestDefaultTransportHasNoProxyAndBoundsRequests(t *testing.T) {
	c, e := NewClient("https://example.invalid/api/v1", nil)
	if e != nil {
		t.Fatal(e)
	}
	transport, ok := c.http.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil || transport.TLSHandshakeTimeout <= 0 || transport.ResponseHeaderTimeout <= 0 || c.http.Timeout <= 0 {
		t.Fatal("unbounded default client or inherited proxy")
	}
}

func TestSentinelErrorsUseRegisteredFailureCodes(t *testing.T) {
	for _, tc := range []struct {
		err  error
		code string
	}{{ErrInput, generated.ErrorCodeInputInvalid}, {ErrIdentity, generated.ErrorCodeIntegrityFailure}, {ErrUnavailable, generated.ErrorCodeDependencyUnavailable}} {
		stable, ok := failure.As(tc.err)
		if !ok || stable.Code != tc.code || stable.Target != "coolify-observation" || stable.Retryable {
			t.Fatalf("unexpected sentinel: %+v", tc.err)
		}
	}
}
