package githubci

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/ci"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
)

func fixtureTarget() Target {
	digest := sha256.Sum256([]byte("name: CI\n"))
	return Target{Enrollment: ci.Enrollment{ID: "ci-one", Binding: ci.Binding{RepositoryID: "10", OwnerID: "20", Repository: "owner/repo", WorkflowID: "30", WorkflowPath: ".github/workflows/ci.yml", WorkflowDigest: "sha256:" + hex.EncodeToString(digest[:]), Revision: strings.Repeat("a", 40), Ref: "refs/heads/main", Event: "push", JobName: "build", RunnerID: "40", RunnerGroupID: "50", Labels: []string{"self-hosted", "isolated"}}}, RunID: "60", JobID: "70", Attempt: 2}
}
func fixtureRepository() map[string]any {
	return map[string]any{"id": 10, "name": "repo", "full_name": "owner/repo", "owner": map[string]any{"id": 20, "login": "owner"}}
}
func fixtureRun() map[string]any {
	return map[string]any{"id": 60, "run_attempt": 2, "workflow_id": 30, "path": ".github/workflows/ci.yml", "head_sha": strings.Repeat("a", 40), "head_branch": "main", "event": "push", "status": "in_progress", "repository": fixtureRepository(), "head_repository": fixtureRepository()}
}
func fixtureJob() map[string]any {
	return map[string]any{"id": 70, "run_id": 60, "head_sha": strings.Repeat("a", 40), "name": "build", "status": "in_progress", "runner_id": 40, "runner_group_id": 50, "labels": []string{"isolated", "self-hosted"}}
}
func fixtureContent() map[string]any {
	return map[string]any{"type": "file", "path": ".github/workflows/ci.yml", "size": 9, "encoding": "base64", "content": base64.StdEncoding.EncodeToString([]byte("name: CI\n"))}
}
func serveFixture(t *testing.T, mutate func(string, int, map[string]any) any, token string) (*Client, *int) {
	t.Helper()
	count := 0
	current := 0
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count++
		if r.Method != "GET" || r.Header.Get("X-GitHub-Api-Version") != "2022-11-28" || r.Header.Get("Accept") != "application/vnd.github+json" {
			t.Error("request contract", r.Method, r.Header)
		}
		expectedAuth := ""
		if token != "" {
			expectedAuth = "Bearer " + token
		}
		if r.Header.Get("Authorization") != expectedAuth {
			t.Error("authorization mismatch")
		}
		var body map[string]any
		switch r.URL.Path {
		case "/repos/owner/repo":
			body = fixtureRepository()
		case "/repos/owner/repo/actions/runs/60":
			current++
			body = fixtureRun()
		case "/repos/owner/repo/actions/runs/60/attempts/2":
			body = fixtureRun()
		case "/repos/owner/repo/actions/runs/60/attempts/2/jobs":
			if r.URL.RawQuery != "page=1&per_page=100" {
				t.Error("jobs query", r.URL.RawQuery)
			}
			body = map[string]any{"total_count": 1, "jobs": []any{fixtureJob()}}
		case "/repos/owner/repo/contents/.github/workflows/ci.yml":
			if r.URL.Query().Get("ref") != strings.Repeat("a", 40) || len(r.URL.Query()) != 1 {
				t.Error("unpinned content")
			}
			body = fixtureContent()
		default:
			t.Error("unexpected route", r.URL.String())
			w.WriteHeader(404)
			return
		}
		var output any = body
		if mutate != nil {
			output = mutate(r.URL.Path, current, body)
		}
		if raw, ok := output.(string); ok {
			fmt.Fprint(w, raw)
		} else {
			json.NewEncoder(w).Encode(output)
		}
	}))
	t.Cleanup(s.Close)
	client, err := NewClient(s.URL, s.Client().Transport)
	if err != nil {
		t.Fatal(err)
	}
	return client, &count
}
func TestObserveExactBinding(t *testing.T) {
	for _, token := range []string{"", "test-secret"} {
		t.Run(token, func(t *testing.T) {
			c, n := serveFixture(t, nil, token)
			var v *credentialref.Value
			if token != "" {
				v, _ = credentialref.NewValue([]byte(token))
				defer v.Close()
			}
			got, err := c.Observe(context.Background(), fixtureTarget(), v)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = ci.Match(fixtureTarget().Enrollment, got, time.Now()); err != nil {
				t.Fatal(err)
			}
			if *n != 6 {
				t.Fatal("request count", *n)
			}
		})
	}
}
func TestObserveRejectsProviderMismatch(t *testing.T) {
	cases := map[string]func(string, int, map[string]any) any{
		"repo": func(p string, _ int, b map[string]any) any {
			if p == "/repos/owner/repo" {
				b["id"] = 999
			}
			return b
		},
		"fork": func(p string, _ int, b map[string]any) any {
			if strings.Contains(p, "/runs/60") && !strings.HasSuffix(p, "jobs") {
				r := fixtureRepository()
				r["id"] = 999
				b["head_repository"] = r
			}
			return b
		},
		"race": func(p string, n int, b map[string]any) any {
			if p == "/repos/owner/repo/actions/runs/60" && n == 2 {
				b["run_attempt"] = 3
			}
			return b
		},
		"workflow": func(p string, _ int, b map[string]any) any {
			if strings.Contains(p, "/runs/60") && !strings.HasSuffix(p, "jobs") {
				b["workflow_id"] = 99
			}
			return b
		},
		"digest": func(p string, _ int, b map[string]any) any {
			if strings.Contains(p, "/contents/") {
				b["content"] = base64.StdEncoding.EncodeToString([]byte("bad file!"))
			}
			return b
		},
		"runner": func(p string, _ int, b map[string]any) any {
			if strings.HasSuffix(p, "jobs") {
				j := fixtureJob()
				j["runner_id"] = 99
				b["jobs"] = []any{j}
			}
			return b
		},
		"membership": func(p string, _ int, b map[string]any) any {
			if strings.HasSuffix(p, "jobs") {
				j := fixtureJob()
				j["run_id"] = 99
				b["jobs"] = []any{j}
			}
			return b
		},
		"duplicate-job": func(p string, _ int, b map[string]any) any {
			if strings.HasSuffix(p, "jobs") {
				b["total_count"] = 2
				b["jobs"] = []any{fixtureJob(), fixtureJob()}
			}
			return b
		},
		"count": func(p string, _ int, b map[string]any) any {
			if strings.HasSuffix(p, "jobs") {
				b["total_count"] = 2
			}
			return b
		},
		"duplicate-json": func(_ string, _ int, _ map[string]any) any { return `{"id":10,"id":10}` },
		"deep": func(_ string, _ int, _ map[string]any) any {
			return `{"a":` + strings.Repeat("[", 70) + "0" + strings.Repeat("]", 70) + "}"
		},
		"oversize": func(_ string, _ int, _ map[string]any) any { return strings.Repeat(" ", 2<<20) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c, _ := serveFixture(t, mutate, "")
			got, err := c.Observe(context.Background(), fixtureTarget(), nil)
			if err == nil || got.RunID != "" {
				t.Fatal("accepted", got, err)
			}
		})
	}
}
func TestRejectInvalidTargetAndCancellation(t *testing.T) {
	c, n := serveFixture(t, nil, "")
	q := fixtureTarget()
	q.RunID = "60/evil"
	if _, err := c.Observe(context.Background(), q, nil); err == nil || *n != 0 {
		t.Fatal("invalid input contacted provider")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Observe(ctx, fixtureTarget(), nil); err == nil {
		t.Fatal("canceled request accepted")
	}
}

func TestProviderFieldDenials(t *testing.T) {
	for _, test := range []struct {
		route, field string
		value        any
	}{
		{"repo", "name", "other"}, {"repo", "full_name", "other/repo"}, {"run", "id", 61}, {"run", "run_attempt", 1}, {"run", "head_sha", strings.Repeat("b", 40)}, {"run", "head_branch", "other"}, {"run", "event", "pull_request_target"}, {"run", "path", ".github/workflows/other.yml"}, {"run", "status", "completed"},
		{"job", "id", 71}, {"job", "head_sha", strings.Repeat("b", 40)}, {"job", "name", "other"}, {"job", "status", "queued"}, {"job", "runner_group_id", 51}, {"job", "labels", []string{"self-hosted"}}, {"job", "labels", []string{"self-hosted", "isolated", "isolated"}},
		{"content", "type", "symlink"}, {"content", "path", "other.yml"}, {"content", "size", 8}, {"content", "encoding", "none"}, {"content", "sha", strings.Repeat("a", 40)}, {"content", "content", "!invalid"},
	} {
		t.Run(test.route+"/"+test.field+fmt.Sprint(test.value), func(t *testing.T) {
			c, _ := serveFixture(t, func(p string, _ int, b map[string]any) any {
				switch test.route {
				case "repo":
					if p == "/repos/owner/repo" {
						b[test.field] = test.value
					}
				case "run":
					if strings.Contains(p, "/runs/60") && !strings.HasSuffix(p, "jobs") {
						b[test.field] = test.value
					}
				case "job":
					if strings.HasSuffix(p, "jobs") {
						j := fixtureJob()
						j[test.field] = test.value
						b["jobs"] = []any{j}
					}
				case "content":
					if strings.Contains(p, "/contents/") {
						b[test.field] = test.value
					}
				}
				return b
			}, "")
			if _, err := c.Observe(context.Background(), fixtureTarget(), nil); err == nil {
				t.Fatal("accepted mismatched field")
			}
		})
	}
}

func TestWorkflowRefSuffix(t *testing.T) {
	c, _ := serveFixture(t, func(p string, _ int, b map[string]any) any {
		if strings.Contains(p, "/runs/60") && !strings.HasSuffix(p, "jobs") {
			b["path"] = ".github/workflows/ci.yml@refs/heads/main"
		}
		return b
	}, "")
	if _, err := c.Observe(context.Background(), fixtureTarget(), nil); err != nil {
		t.Fatal(err)
	}
}

func TestInvalidOrigins(t *testing.T) {
	for _, base := range []string{"http://example.com", "https://user:password@example.com", "https://example.com?x=1", "https://example.com/#x", "https://example.com/a/../b", "https://example.com/%2f"} {
		if _, err := NewClient(base, nil); err == nil {
			t.Fatal("accepted", base)
		}
	}
}

func TestStatusRedirectAndRedaction(t *testing.T) {
	for _, status := range []int{301, 302, 307, 401, 403, 404, 429, 500} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			count := 0
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				count++
				w.Header().Set("Location", "https://untrusted.invalid/test-secret")
				w.WriteHeader(status)
				fmt.Fprint(w, "test-secret provider error")
			}))
			defer s.Close()
			c, _ := NewClient(s.URL, s.Client().Transport)
			v, _ := credentialref.NewValue([]byte("test-secret"))
			defer v.Close()
			got, err := c.Observe(context.Background(), fixtureTarget(), v)
			if err == nil || strings.Contains(err.Error(), "test-secret") || got.RunID != "" || count != 1 {
				t.Fatal("unsafe response handling", got, err, count)
			}
		})
	}
	for _, raw := range []string{" ", "null", "[]", "{} {}", "{\"id\":10,\"owner\":{\"id\":20,\"id\":20}}"} {
		t.Run(raw, func(t *testing.T) {
			c, _ := serveFixture(t, func(string, int, map[string]any) any { return raw }, "")
			if _, err := c.Observe(context.Background(), fixtureTarget(), nil); err == nil {
				t.Fatal("invalid JSON accepted")
			}
		})
	}
}

func TestBoundedCompletePagination(t *testing.T) {
	for _, mode := range []string{"complete", "duplicate", "count-changed", "too-many", "empty-page"} {
		t.Run(mode, func(t *testing.T) {
			pages := 0
			c, _ := serveFixture(t, nil, "")
			original := c.http.Transport
			c.http.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if !strings.HasSuffix(r.URL.Path, "/jobs") {
					return original.RoundTrip(r)
				}
				pages++
				if r.URL.Query().Get("page") != fmt.Sprint(pages) || r.URL.Query().Get("per_page") != "100" {
					t.Error("wrong page")
				}
				total := 101
				if mode == "too-many" {
					total = 1001
				}
				if mode == "count-changed" && pages == 2 {
					total = 102
				}
				jobs := []any{}
				if pages == 1 {
					for i := 0; i < 100; i++ {
						j := fixtureJob()
						j["id"] = 1000 + i
						jobs = append(jobs, j)
					}
				} else {
					j := fixtureJob()
					if mode == "duplicate" {
						j["id"] = 1000
					}
					if mode != "empty-page" {
						jobs = append(jobs, j)
					}
				}
				b, _ := json.Marshal(map[string]any{"total_count": total, "jobs": jobs})
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(b))), Header: make(http.Header)}, nil
			})
			_, err := c.Observe(context.Background(), fixtureTarget(), nil)
			if (err == nil) != (mode == "complete") {
				t.Fatal("pagination outcome", err)
			}
			if pages > 2 {
				t.Fatal("unbounded pagination")
			}
		})
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestNoImplicitCredentialAndInvalidCredentials(t *testing.T) {
	t.Setenv("GH_TOKEN", "environment-secret")
	t.Setenv("GITHUB_TOKEN", "environment-secret")
	c, n := serveFixture(t, nil, "")
	if _, err := c.Observe(context.Background(), fixtureTarget(), nil); err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{"bad\r\ntoken", " padded", "bad\x00token"} {
		v, _ := credentialref.NewValue([]byte(token))
		before := *n
		if _, err := c.Observe(context.Background(), fixtureTarget(), v); err == nil || *n != before {
			t.Fatal("invalid credential contacted provider")
		}
		v.Close()
	}
	v, _ := credentialref.NewValue([]byte("closed"))
	v.Close()
	before := *n
	if _, err := c.Observe(context.Background(), fixtureTarget(), v); err == nil || *n != before {
		t.Fatal("closed credential accepted")
	}
}
func TestCancellationDuringRequest(t *testing.T) {
	c, _ := NewClient("https://configured.invalid", roundTripFunc(func(r *http.Request) (*http.Response, error) {
		<-r.Context().Done()
		return nil, fmt.Errorf("secret-in-transport: %w", r.Context().Err())
	}))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := c.Observe(ctx, fixtureTarget(), nil)
	if err == nil || strings.Contains(err.Error(), "secret") || time.Since(start) > time.Second {
		t.Fatal("cancellation or sanitization failed", err)
	}
}
func TestOptionalGitBlobSHA(t *testing.T) {
	c, _ := serveFixture(t, func(p string, _ int, b map[string]any) any {
		if strings.Contains(p, "/contents/") {
			blob := sha1.Sum([]byte("blob 9\x00name: CI\n"))
			b["sha"] = hex.EncodeToString(blob[:])
		}
		return b
	}, "")
	if _, err := c.Observe(context.Background(), fixtureTarget(), nil); err != nil {
		t.Fatal(err)
	}
}
