package githubci

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
)

func registrationRequest() RunnerRegistrationRequest {
	return RunnerRegistrationRequest{Organization: OrganizationTarget{Login: "owner", ID: 20}, Repository: "owner/repo", RepositoryID: "10", RepositoryOwnerID: "20", GroupName: "isolated", GroupID: 50, Check: func() error { return nil }}
}
func cleanupRequest() RunnerCleanupRequest {
	return RunnerCleanupRequest{Organization: OrganizationTarget{Login: "owner", ID: 20}, RunnerID: 40, Name: "owned-one", OS: "linux", Labels: []string{"self-hosted", "isolated"}, Check: func() error { return nil }}
}
func adminValue(t *testing.T) *credentialref.Value {
	t.Helper()
	v, e := credentialref.NewValue([]byte("admin-secret"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(v.Close)
	return v
}
func runnerFixture(t *testing.T, mutate func(*http.Request, map[string]any) (int, any)) (*Client, *[]string) {
	t.Helper()
	calls := []string{}
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.RequestURI())
		if r.Header.Get("Authorization") != "Bearer admin-secret" || r.Header.Get("X-GitHub-Api-Version") != "2022-11-28" || r.Header.Get("Accept") != "application/vnd.github+json" {
			t.Error("bad headers")
		}
		code := 200
		var b map[string]any
		switch r.Method + " " + r.URL.Path {
		case "GET /orgs/owner":
			b = map[string]any{"id": 20, "login": "owner"}
		case "GET /repos/owner/repo":
			b = fixtureRepository()
		case "GET /orgs/owner/actions/runner-groups/50":
			b = map[string]any{"id": 50, "name": "isolated", "visibility": "selected"}
		case "GET /orgs/owner/actions/runner-groups/50/repositories":
			if r.URL.RawQuery != "page=1&per_page=100" {
				t.Error("unbounded query")
			}
			b = map[string]any{"total_count": 1, "repositories": []any{fixtureRepository()}}
		case "POST /orgs/owner/actions/runners/registration-token":
			code = 201
			b = map[string]any{"token": "registration-secret", "expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}
		case "GET /orgs/owner/actions/runners/40":
			b = map[string]any{"id": 40, "name": "owned-one", "os": "linux", "status": "offline", "busy": false, "labels": []any{map[string]any{"name": "isolated"}, map[string]any{"name": "self-hosted"}}}
		case "DELETE /orgs/owner/actions/runners/40":
			code = 204
		default:
			t.Error("unexpected route", r.Method, r.URL.String())
			code = 404
		}
		var out any = b
		if mutate != nil {
			code, out = mutate(r, b)
		}
		w.WriteHeader(code)
		if code != 204 {
			if raw, ok := out.(string); ok {
				fmt.Fprint(w, raw)
			} else {
				json.NewEncoder(w).Encode(out)
			}
		}
	}))
	t.Cleanup(s.Close)
	c, e := NewClient(s.URL, s.Client().Transport)
	if e != nil {
		t.Fatal(e)
	}
	return c, &calls
}
func TestPrepareRegistration(t *testing.T) {
	c, calls := runnerFixture(t, nil)
	var retained *credentialref.Value
	var borrowed []byte
	q := registrationRequest()
	checks := 0
	q.Check = func() error { checks++; return nil }
	out, e := c.PrepareRegistration(context.Background(), q, adminValue(t), func(ctx context.Context, v *credentialref.Value, expiry time.Time) error {
		if string(v.Bytes()) != "registration-secret" || !expiry.After(time.Now()) {
			t.Fatal("bad token")
		}
		retained = v
		borrowed = v.Bytes()
		return nil
	})
	if e != nil || out.Stage != "consumed" || out.ExpiresAt.IsZero() {
		t.Fatal(out, e)
	}
	if len(retained.Bytes()) != 0 {
		t.Fatal("token retained")
	}
	for _, b := range borrowed {
		if b != 0 {
			t.Fatal("borrow not wiped")
		}
	}
	if len(*calls) != 5 || checks != 6 {
		t.Fatal("requests/checks", calls, checks)
	}
}
func TestRegistrationScopeDenial(t *testing.T) {
	c, calls := runnerFixture(t, func(r *http.Request, b map[string]any) (int, any) {
		if strings.HasSuffix(r.URL.Path, "runner-groups/50") {
			b["visibility"] = "all"
		}
		return 200, b
	})
	called := false
	_, e := c.PrepareRegistration(context.Background(), registrationRequest(), adminValue(t), func(context.Context, *credentialref.Value, time.Time) error { called = true; return nil })
	if e == nil || called || len(*calls) != 3 {
		t.Fatal("scope widened", e, calls)
	}
}
func TestRemoveOwnedRunner(t *testing.T) {
	c, calls := runnerFixture(t, nil)
	out, e := c.RemoveOwnedRunner(context.Background(), cleanupRequest(), adminValue(t))
	if e != nil || out.Stage != "deleted" || out.Absent || len(*calls) != 3 {
		t.Fatal(out, e, calls)
	}
}

func fixtureStatus(r *http.Request) int {
	if r.Method == http.MethodPost {
		return 201
	}
	if r.Method == http.MethodDelete {
		return 204
	}
	return 200
}
func TestRegistrationIdentityAndTokenDenials(t *testing.T) {
	for _, tc := range []struct {
		route, key string
		value      any
	}{
		{"/orgs/owner", "id", 21}, {"/orgs/owner", "login", "other"}, {"/repos/owner/repo", "id", 11}, {"/repos/owner/repo", "full_name", "owner/other"}, {"/orgs/owner/actions/runner-groups/50", "id", 51}, {"/orgs/owner/actions/runner-groups/50", "name", "other"}, {"/orgs/owner/actions/runner-groups/50", "visibility", "private"},
		{"/orgs/owner/actions/runner-groups/50/repositories", "repositories", []any{}}, {"/orgs/owner/actions/runner-groups/50/repositories", "total_count", 1001},
		{"/orgs/owner/actions/runners/registration-token", "token", ""}, {"/orgs/owner/actions/runners/registration-token", "token", "bad token"}, {"/orgs/owner/actions/runners/registration-token", "token", strings.Repeat("a", 4097)}, {"/orgs/owner/actions/runners/registration-token", "expires_at", "bad"}, {"/orgs/owner/actions/runners/registration-token", "expires_at", time.Now().Add(-time.Minute).Format(time.RFC3339)}, {"/orgs/owner/actions/runners/registration-token", "expires_at", time.Now().Add(24 * time.Hour).Format(time.RFC3339)},
	} {
		t.Run(tc.route+tc.key+fmt.Sprint(tc.value), func(t *testing.T) {
			c, _ := runnerFixture(t, func(r *http.Request, b map[string]any) (int, any) {
				if r.URL.Path == tc.route {
					b[tc.key] = tc.value
				}
				return fixtureStatus(r), b
			})
			called := false
			out, e := c.PrepareRegistration(context.Background(), registrationRequest(), adminValue(t), func(context.Context, *credentialref.Value, time.Time) error { called = true; return nil })
			if e == nil || called {
				t.Fatal("invalid binding/token accepted", out, e)
			}
			if strings.HasSuffix(tc.route, "registration-token") && out.Stage != "token-request-attempted" {
				t.Fatal("attempt not retained", out)
			}
		})
	}
}
func TestCleanupDenialsAndAbsence(t *testing.T) {
	for _, tc := range []struct {
		key   string
		value any
	}{{"id", 41}, {"name", "other"}, {"os", "windows"}, {"status", "online"}, {"busy", true}, {"busy", nil}, {"labels", []any{map[string]any{"name": "self-hosted"}}}, {"labels", []any{map[string]any{"name": "isolated"}, map[string]any{"name": "isolated"}}}} {
		t.Run(tc.key+fmt.Sprint(tc.value), func(t *testing.T) {
			c, calls := runnerFixture(t, func(r *http.Request, b map[string]any) (int, any) {
				if strings.HasSuffix(r.URL.Path, "runners/40") {
					b[tc.key] = tc.value
				}
				return fixtureStatus(r), b
			})
			out, e := c.RemoveOwnedRunner(context.Background(), cleanupRequest(), adminValue(t))
			if e == nil || out.Stage != "" || len(*calls) != 2 {
				t.Fatal("unsafe delete", out, e, calls)
			}
		})
	}
	c, calls := runnerFixture(t, func(r *http.Request, b map[string]any) (int, any) {
		if strings.HasSuffix(r.URL.Path, "runners/40") {
			return 404, "secret"
		}
		return 200, b
	})
	out, e := c.RemoveOwnedRunner(context.Background(), cleanupRequest(), adminValue(t))
	if e != nil || !out.Absent || out.Stage != "absent" || len(*calls) != 2 {
		t.Fatal(out, e, calls)
	}
}
func TestCheckBeforeEveryRequestAndConsumption(t *testing.T) {
	for failAt := 1; failAt <= 6; failAt++ {
		t.Run(fmt.Sprint(failAt), func(t *testing.T) {
			c, calls := runnerFixture(t, nil)
			q := registrationRequest()
			checks := 0
			q.Check = func() error {
				checks++
				if checks == failAt {
					return fmt.Errorf("check-secret")
				}
				return nil
			}
			called := false
			out, e := c.PrepareRegistration(context.Background(), q, adminValue(t), func(context.Context, *credentialref.Value, time.Time) error { called = true; return nil })
			if e == nil || called || strings.Contains(e.Error(), "secret") || len(*calls) != min(failAt-1, 5) {
				t.Fatal(out, e, calls)
			}
			if (out.Stage == "token-request-attempted") != (failAt == 6) {
				t.Fatal("wrong attempt", out)
			}
		})
	}
	c, calls := runnerFixture(t, nil)
	q := cleanupRequest()
	checks := 0
	q.Check = func() error {
		checks++
		if checks == 3 {
			return fmt.Errorf("secret")
		}
		return nil
	}
	out, e := c.RemoveOwnedRunner(context.Background(), q, adminValue(t))
	if e == nil || out.Stage != "" || len(*calls) != 2 {
		t.Fatal("delete bypassed check", out, e, calls)
	}
}
func TestTokenClosedOnConsumerErrorAndPanic(t *testing.T) {
	for _, panicConsumer := range []bool{false, true} {
		t.Run(fmt.Sprint(panicConsumer), func(t *testing.T) {
			c, _ := runnerFixture(t, nil)
			var retained *credentialref.Value
			var borrowed []byte
			func() {
				defer func() {
					if p := recover(); p != nil && !panicConsumer {
						t.Fatal("unexpected panic")
					}
				}()
				out, e := c.PrepareRegistration(context.Background(), registrationRequest(), adminValue(t), func(_ context.Context, v *credentialref.Value, _ time.Time) error {
					retained = v
					borrowed = v.Bytes()
					if panicConsumer {
						panic("consumer panic")
					}
					return fmt.Errorf("consumer-secret")
				})
				if e == nil || out.Stage != "token-request-attempted" || strings.Contains(e.Error(), "consumer-secret") {
					t.Fatal(out, e)
				}
			}()
			if retained == nil || len(retained.Bytes()) != 0 {
				t.Fatal("token escaped consumer")
			}
			for _, b := range borrowed {
				if b != 0 {
					t.Fatal("token bytes not wiped")
				}
			}
		})
	}
}
func TestRunnerMalformedStatusAndLostResponses(t *testing.T) {
	for _, raw := range []string{`{"token":"registration-secret","token":"registration-secret"}`, " ", "null", `{"x":` + strings.Repeat("[", 40) + "0" + strings.Repeat("]", 40) + "}", strings.Repeat(" ", maxBody+1)} {
		t.Run(fmt.Sprint(len(raw)), func(t *testing.T) {
			c, _ := runnerFixture(t, func(r *http.Request, b map[string]any) (int, any) {
				if r.Method == http.MethodPost {
					return 201, raw
				}
				return 200, b
			})
			out, e := c.PrepareRegistration(context.Background(), registrationRequest(), adminValue(t), func(context.Context, *credentialref.Value, time.Time) error {
				t.Fatal("malformed token consumed")
				return nil
			})
			if e == nil || out.Stage != "token-request-attempted" {
				t.Fatal(out, e)
			}
		})
	}
	for _, status := range []int{302, 401, 403, 404, 429, 500} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			c, calls := runnerFixture(t, func(r *http.Request, b map[string]any) (int, any) {
				if r.Method == http.MethodPost {
					return status, "provider-secret"
				}
				return 200, b
			})
			out, e := c.PrepareRegistration(context.Background(), registrationRequest(), adminValue(t), func(context.Context, *credentialref.Value, time.Time) error { return nil })
			if e == nil || strings.Contains(e.Error(), "provider-secret") || out.Stage != "token-request-attempted" || len(*calls) != 5 {
				t.Fatal(out, e, calls)
			}
		})
	}
	for _, method := range []string{http.MethodPost, http.MethodDelete} {
		t.Run("lost-"+method, func(t *testing.T) {
			c, _ := runnerFixture(t, nil)
			original := c.http.Transport
			attempts := 0
			c.http.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.Method == method {
					attempts++
					return nil, fmt.Errorf("transport-secret")
				}
				return original.RoundTrip(r)
			})
			if method == http.MethodPost {
				out, e := c.PrepareRegistration(context.Background(), registrationRequest(), adminValue(t), func(context.Context, *credentialref.Value, time.Time) error { return nil })
				if e == nil || out.Stage != "token-request-attempted" || strings.Contains(e.Error(), "secret") {
					t.Fatal(out, e)
				}
			} else {
				out, e := c.RemoveOwnedRunner(context.Background(), cleanupRequest(), adminValue(t))
				if e == nil || out.Stage != "delete-attempted" || strings.Contains(e.Error(), "secret") {
					t.Fatal(out, e)
				}
			}
			if attempts != 1 {
				t.Fatal("retried mutation")
			}
		})
	}
}

func TestSelectedRepositoryPagination(t *testing.T) {
	for _, mode := range []string{"complete", "duplicate", "changed", "incomplete", "missing"} {
		t.Run(mode, func(t *testing.T) {
			c, _ := runnerFixture(t, nil)
			original := c.http.Transport
			pages := 0
			c.http.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if !strings.HasSuffix(r.URL.Path, "/repositories") {
					return original.RoundTrip(r)
				}
				pages++
				if r.URL.Query().Get("page") != fmt.Sprint(pages) || r.URL.Query().Get("per_page") != "100" {
					t.Fatal("pagination query")
				}
				repos := []any{}
				if pages == 1 {
					for i := 0; i < 100; i++ {
						repo := fixtureRepository()
						repo["id"] = 1000 + i
						repos = append(repos, repo)
					}
				} else {
					repo := fixtureRepository()
					if mode == "duplicate" {
						repo["id"] = 1000
					}
					if mode == "missing" {
						repo["id"] = 11
					}
					if mode != "incomplete" {
						repos = append(repos, repo)
					}
				}
				count := 101
				if mode == "changed" && pages == 2 {
					count = 102
				}
				body, _ := json.Marshal(map[string]any{"total_count": count, "repositories": repos})
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(body)))}, nil
			})
			out, e := c.PrepareRegistration(context.Background(), registrationRequest(), adminValue(t), func(context.Context, *credentialref.Value, time.Time) error { return nil })
			if (e == nil) != (mode == "complete") || pages != 2 {
				t.Fatal(out, e, pages)
			}
		})
	}
}
func TestRunnerCancellationAndInput(t *testing.T) {
	c, calls := runnerFixture(t, nil)
	q := registrationRequest()
	q.RepositoryOwnerID = "21"
	if _, e := c.PrepareRegistration(context.Background(), q, adminValue(t), func(context.Context, *credentialref.Value, time.Time) error { return nil }); e == nil || len(*calls) != 0 {
		t.Fatal("cross-owner request")
	}
	q = registrationRequest()
	q.Check = nil
	if _, e := c.PrepareRegistration(context.Background(), q, adminValue(t), func(context.Context, *credentialref.Value, time.Time) error { return nil }); e == nil || len(*calls) != 0 {
		t.Fatal("missing check accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := c.RemoveOwnedRunner(ctx, cleanupRequest(), adminValue(t)); e == nil || len(*calls) != 0 {
		t.Fatal("cancel ignored")
	}
	original := c.http.Transport
	c.http.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodPost {
			<-r.Context().Done()
			return nil, r.Context().Err()
		}
		return original.RoundTrip(r)
	})
	ctx, cancel = context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	out, e := c.PrepareRegistration(ctx, registrationRequest(), adminValue(t), func(context.Context, *credentialref.Value, time.Time) error {
		t.Fatal("canceled token consumed")
		return nil
	})
	if e == nil || out.Stage != "token-request-attempted" {
		t.Fatal(out, e)
	}
}
func TestActualNetworkResponseLoss(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			attempts := 0
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == method {
					attempts++
					conn, _, e := w.(http.Hijacker).Hijack()
					if e != nil {
						t.Error(e)
						return
					}
					conn.Close()
					return
				}
				var body any
				switch r.URL.Path {
				case "/orgs/owner":
					body = map[string]any{"id": 20, "login": "owner"}
				case "/repos/owner/repo":
					body = fixtureRepository()
				case "/orgs/owner/actions/runner-groups/50":
					body = map[string]any{"id": 50, "name": "isolated", "visibility": "selected"}
				case "/orgs/owner/actions/runner-groups/50/repositories":
					body = map[string]any{"total_count": 1, "repositories": []any{fixtureRepository()}}
				case "/orgs/owner/actions/runners/40":
					body = map[string]any{"id": 40, "name": "owned-one", "os": "linux", "status": "offline", "busy": false, "labels": []any{map[string]any{"name": "self-hosted"}, map[string]any{"name": "isolated"}}}
				default:
					t.Error("unexpected path")
				}
				json.NewEncoder(w).Encode(body)
			}))
			defer s.Close()
			c, _ := NewClient(s.URL, s.Client().Transport)
			if method == http.MethodPost {
				out, e := c.PrepareRegistration(context.Background(), registrationRequest(), adminValue(t), func(context.Context, *credentialref.Value, time.Time) error { return nil })
				if e == nil || out.Stage != "token-request-attempted" {
					t.Fatal(out, e)
				}
			} else {
				out, e := c.RemoveOwnedRunner(context.Background(), cleanupRequest(), adminValue(t))
				if e == nil || out.Stage != "delete-attempted" {
					t.Fatal(out, e)
				}
			}
			if attempts != 1 {
				t.Fatal("retry after loss", attempts)
			}
		})
	}
}
