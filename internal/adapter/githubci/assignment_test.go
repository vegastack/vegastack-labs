package githubci

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/ci"
)

func assignmentTarget() AssignmentTarget {
	t := fixtureTarget()
	return AssignmentTarget{Enrollment: t.Enrollment, RunnerName: "owned-one", RunnerOS: "linux", GroupName: "isolated", RunID: t.RunID, Attempt: t.Attempt, Check: func() error { return nil }}
}
func assignmentRunnerBody() map[string]any {
	return map[string]any{"id": 40, "name": "owned-one", "os": "linux", "status": "online", "busy": true, "labels": []any{map[string]any{"name": "isolated"}, map[string]any{"name": "self-hosted"}}}
}
func assignmentFixture(t *testing.T, mutate func(string, int, map[string]any) any) (*Client, *[]string) {
	t.Helper()
	calls := []string{}
	seen := map[string]int{}
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		calls = append(calls, r.Method+" "+r.URL.RequestURI())
		seen[path]++
		if r.Method != "GET" || r.Header.Get("Authorization") != "Bearer admin-secret" || r.Header.Get("X-GitHub-Api-Version") != "2022-11-28" {
			t.Error("request contract")
		}
		var b map[string]any
		switch path {
		case "/orgs/owner":
			b = map[string]any{"id": 20, "login": "owner"}
		case "/repos/owner/repo":
			b = fixtureRepository()
		case "/orgs/owner/actions/runner-groups/50":
			b = map[string]any{"id": 50, "name": "isolated", "visibility": "selected"}
		case "/orgs/owner/actions/runner-groups/50/repositories":
			b = map[string]any{"total_count": 1, "repositories": []any{fixtureRepository()}}
		case "/orgs/owner/actions/runner-groups/50/runners":
			b = map[string]any{"total_count": 1, "runners": []any{assignmentRunnerBody()}}
		case "/orgs/owner/actions/runners/40":
			b = assignmentRunnerBody()
		case "/repos/owner/repo/actions/runs/60", "/repos/owner/repo/actions/runs/60/attempts/2":
			b = fixtureRun()
		case "/repos/owner/repo/actions/runs/60/attempts/2/jobs":
			b = map[string]any{"total_count": 1, "jobs": []any{fixtureJob()}}
		case "/repos/owner/repo/contents/.github/workflows/ci.yml":
			b = fixtureContent()
			if r.URL.RawQuery != "ref="+strings.Repeat("a", 40) {
				t.Error("unbound workflow")
			}
		default:
			t.Error("unexpected route", path)
			w.WriteHeader(404)
			return
		}
		if strings.HasSuffix(path, "/jobs") || strings.HasSuffix(path, "/repositories") || strings.HasSuffix(path, "/50/runners") {
			if !strings.HasSuffix(r.URL.RawQuery, "&per_page=100") || r.URL.Query().Get("page") == "" {
				t.Error("unbounded page", r.URL.RawQuery)
			}
		}
		var out any = b
		if mutate != nil {
			out = mutate(path, seen[path], b)
		}
		if raw, ok := out.(string); ok {
			fmt.Fprint(w, raw)
		} else {
			json.NewEncoder(w).Encode(out)
		}
	}))
	t.Cleanup(s.Close)
	c, e := NewClient(s.URL, s.Client().Transport)
	if e != nil {
		t.Fatal(e)
	}
	return c, &calls
}
func TestFindAssignedJobExactRead(t *testing.T) {
	c, calls := assignmentFixture(t, nil)
	q := assignmentTarget()
	before := q.Enrollment.Binding.Labels[0]
	checks := 0
	q.Check = func() error {
		checks++
		if checks != len(*calls)+1 {
			t.Errorf("check before request %d %d", checks, len(*calls))
		}
		return nil
	}
	v := adminValue(t)
	got, e := c.FindAssignedJob(context.Background(), q, v)
	if e != nil {
		t.Fatal(e)
	}
	if got.JobID != "70" || got.RunID != "60" || got.Attempt != 2 || got.Binding.RunnerID != "40" || checks != len(*calls)+1 {
		t.Fatal(got, checks, *calls)
	}
	if q.Enrollment.Binding.Labels[0] != before || string(v.Bytes()) != "admin-secret" {
		t.Fatal("mutated borrowed input")
	}
	got.Binding.Labels[0] = "changed"
	if q.Enrollment.Binding.Labels[0] != before {
		t.Fatal("aliased result")
	}
}
func TestFindAssignedJobDenials(t *testing.T) {
	cases := []struct {
		name, path string
		at         int
		change     func(map[string]any) any
	}{
		{"org", "/orgs/owner", 1, func(b map[string]any) any { b["id"] = 21; return b }},
		{"repo", "/repos/owner/repo", 1, func(b map[string]any) any { b["id"] = 11; return b }},
		{"visibility", "/orgs/owner/actions/runner-groups/50", 1, func(b map[string]any) any { b["visibility"] = "all"; return b }},
		{"group-name", "/orgs/owner/actions/runner-groups/50", 1, func(b map[string]any) any { b["name"] = "other"; return b }},
		{"access-revoked", "/orgs/owner/actions/runner-groups/50/repositories", 2, func(b map[string]any) any { b["repositories"] = []any{}; return b }},
		{"runner-name", "/orgs/owner/actions/runners/40", 1, func(b map[string]any) any { b["name"] = "other"; return b }},
		{"runner-id", "/orgs/owner/actions/runners/40", 1, func(b map[string]any) any { b["id"] = 41; return b }},
		{"runner-os", "/orgs/owner/actions/runners/40", 1, func(b map[string]any) any { b["os"] = "osx"; return b }},
		{"runner-offline", "/orgs/owner/actions/runners/40", 1, func(b map[string]any) any { b["status"] = "offline"; return b }},
		{"runner-idle", "/orgs/owner/actions/runners/40", 1, func(b map[string]any) any { b["busy"] = false; return b }},
		{"runner-null-busy", "/orgs/owner/actions/runners/40", 1, func(b map[string]any) any { b["busy"] = nil; return b }},
		{"runner-labels", "/orgs/owner/actions/runners/40", 1, func(b map[string]any) any { b["labels"] = []any{}; return b }},
		{"runner-race", "/orgs/owner/actions/runners/40", 2, func(b map[string]any) any { b["name"] = "other"; return b }},
		{"group-moved", "/orgs/owner/actions/runner-groups/50/runners", 2, func(b map[string]any) any {
			r := assignmentRunnerBody()
			r["id"] = 41
			b["runners"] = []any{r}
			return b
		}},
		{"duplicate-member", "/orgs/owner/actions/runner-groups/50/runners", 1, func(b map[string]any) any {
			b["total_count"] = 2
			b["runners"] = []any{assignmentRunnerBody(), assignmentRunnerBody()}
			return b
		}},
		{"no-job", "/repos/owner/repo/actions/runs/60/attempts/2/jobs", 1, func(b map[string]any) any { j := fixtureJob(); j["runner_id"] = 41; b["jobs"] = []any{j}; return b }},
		{"two-jobs", "/repos/owner/repo/actions/runs/60/attempts/2/jobs", 1, func(b map[string]any) any {
			j := fixtureJob()
			j["id"] = 71
			b["total_count"] = 2
			b["jobs"] = []any{fixtureJob(), j}
			return b
		}},
		{"duplicate-job", "/repos/owner/repo/actions/runs/60/attempts/2/jobs", 1, func(b map[string]any) any {
			b["total_count"] = 2
			b["jobs"] = []any{fixtureJob(), fixtureJob()}
			return b
		}},
		{"wrong-job-name", "/repos/owner/repo/actions/runs/60/attempts/2/jobs", 1, func(b map[string]any) any { j := fixtureJob(); j["name"] = "other"; b["jobs"] = []any{j}; return b }},
		{"job-race", "/repos/owner/repo/actions/runs/60/attempts/2/jobs", 2, func(b map[string]any) any { j := fixtureJob(); j["runner_id"] = 41; b["jobs"] = []any{j}; return b }},
		{"attempt-race", "/repos/owner/repo/actions/runs/60", 4, func(b map[string]any) any { b["run_attempt"] = 3; return b }},
		{"workflow", "/repos/owner/repo/contents/.github/workflows/ci.yml", 1, func(b map[string]any) any { b["content"] = "ZmFrZQo="; return b }},
		{"duplicate-json", "/orgs/owner", 1, func(map[string]any) any { return `{"id":20,"id":20,"login":"owner"}` }},
		{"oversize", "/orgs/owner", 1, func(map[string]any) any { return strings.Repeat("x", maxBody+1) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			changed := false
			c, _ := assignmentFixture(t, func(path string, n int, b map[string]any) any {
				if path == tc.path && n == tc.at {
					changed = true
					return tc.change(b)
				}
				return b
			})
			got, e := c.FindAssignedJob(context.Background(), assignmentTarget(), adminValue(t))
			if !changed || e == nil || !reflect.DeepEqual(got, ci.Observation{}) {
				t.Fatal("missing denial", changed, got, e)
			}
			if strings.Contains(e.Error(), "admin-secret") {
				t.Fatal("secret error")
			}
		})
	}
}
func TestFindAssignedJobChecksEveryRequest(t *testing.T) {
	c, calls := assignmentFixture(t, nil)
	q := assignmentTarget()
	if _, e := c.FindAssignedJob(context.Background(), q, adminValue(t)); e != nil {
		t.Fatal(e)
	}
	total := len(*calls)
	for stop := 1; stop <= total+1; stop++ {
		t.Run(fmt.Sprint(stop), func(t *testing.T) {
			c, calls := assignmentFixture(t, nil)
			q := assignmentTarget()
			n := 0
			q.Check = func() error {
				n++
				if n == stop {
					return errors.New("private callback detail")
				}
				return nil
			}
			got, e := c.FindAssignedJob(context.Background(), q, adminValue(t))
			if e == nil || len(*calls) != min(stop-1, total) || !reflect.DeepEqual(got, ci.Observation{}) || strings.Contains(e.Error(), "private callback") {
				t.Fatal(n, len(*calls), e)
			}
		})
	}
}
func TestFindAssignedJobInvalidInput(t *testing.T) {
	for _, edit := range []func(*AssignmentTarget){func(q *AssignmentTarget) { q.Check = nil }, func(q *AssignmentTarget) { q.RunID = "060" }, func(q *AssignmentTarget) { q.Attempt = 0 }, func(q *AssignmentTarget) { q.Enrollment.Binding.RunnerID = "0" }, func(q *AssignmentTarget) { q.RunnerName = "" }, func(q *AssignmentTarget) { q.RunnerOS = "root" }, func(q *AssignmentTarget) { q.GroupName = "" }} {
		c, calls := assignmentFixture(t, nil)
		q := assignmentTarget()
		edit(&q)
		if _, e := c.FindAssignedJob(context.Background(), q, adminValue(t)); e == nil || len(*calls) != 0 {
			t.Fatal("invalid accepted", e)
		}
	}
	c, calls := assignmentFixture(t, nil)
	if _, e := c.FindAssignedJob(context.Background(), assignmentTarget(), nil); e == nil || len(*calls) != 0 {
		t.Fatal("credential optional")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := c.FindAssignedJob(ctx, assignmentTarget(), adminValue(t)); e == nil || len(*calls) != 0 {
		t.Fatal("cancelled dispatched")
	}
}

func TestFindAssignedJobMembershipPagination(t *testing.T) {
	for _, mode := range []string{"complete", "missing", "duplicate", "count-drift", "over-limit", "short-page"} {
		t.Run(mode, func(t *testing.T) {
			c, _ := assignmentFixture(t, func(path string, n int, b map[string]any) any {
				if path != "/orgs/owner/actions/runner-groups/50/runners" {
					return b
				}
				if mode == "over-limit" {
					b["total_count"] = 1001
					return b
				}
				b["total_count"] = 101
				if n%2 == 1 {
					members := []any{}
					for i := 0; i < 100; i++ {
						r := assignmentRunnerBody()
						r["id"] = 1000 + i
						members = append(members, r)
					}
					if mode == "short-page" {
						members = members[:99]
					}
					b["runners"] = members
				} else {
					r := assignmentRunnerBody()
					if mode == "missing" {
						r["id"] = 999
					}
					if mode == "duplicate" {
						r["id"] = 1000
					}
					if mode == "count-drift" {
						b["total_count"] = 102
					}
					b["runners"] = []any{r}
				}
				return b
			})
			got, e := c.FindAssignedJob(context.Background(), assignmentTarget(), adminValue(t))
			if mode == "complete" {
				if e != nil || got.JobID != "70" {
					t.Fatal(got, e)
				}
			} else if e == nil || !reflect.DeepEqual(got, ci.Observation{}) {
				t.Fatal("pagination denial missing", got, e)
			}
		})
	}
}
func TestFindAssignedJobSecondSnapshotUnique(t *testing.T) {
	c, _ := assignmentFixture(t, func(path string, n int, b map[string]any) any {
		if strings.HasSuffix(path, "/jobs") && n == 2 {
			j := fixtureJob()
			j["id"] = 71
			b["total_count"] = 2
			b["jobs"] = []any{fixtureJob(), j}
		}
		return b
	})
	if got, e := c.FindAssignedJob(context.Background(), assignmentTarget(), adminValue(t)); e == nil || !reflect.DeepEqual(got, ci.Observation{}) {
		t.Fatal("second snapshot ambiguity accepted", got, e)
	}
}
func TestFindAssignedJobFailureTransport(t *testing.T) {
	for _, status := range []int{301, 401, 403, 404, 429, 500} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			hits := 0
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits++
				w.Header().Set("Location", "https://untrusted.invalid/secret")
				w.WriteHeader(status)
				fmt.Fprint(w, "admin-secret provider-private")
			}))
			defer s.Close()
			c, e := NewClient(s.URL, s.Client().Transport)
			if e != nil {
				t.Fatal(e)
			}
			got, e := c.FindAssignedJob(context.Background(), assignmentTarget(), adminValue(t))
			if e == nil || hits != 1 || !reflect.DeepEqual(got, ci.Observation{}) || strings.Contains(e.Error(), "admin-secret") || strings.Contains(e.Error(), "provider-private") {
				t.Fatal(hits, got, e)
			}
		})
	}
}
