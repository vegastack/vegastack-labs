package githubci

import (
	"context"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/ci"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func completedFixture(t *testing.T, mutation string) (*Client, *int) {
	t.Helper()
	calls := 0
	currentReads := 0
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != "GET" || r.Header.Get("Authorization") != "Bearer completion-read" {
			t.Error("completion read scope", r.Method)
			w.WriteHeader(401)
			return
		}
		var body any
		switch r.URL.Path {
		case "/orgs/owner":
			body = map[string]any{"id": 20, "login": "owner"}
		case "/orgs/owner/actions/runner-groups/50":
			body = map[string]any{"id": 50, "name": "isolated", "visibility": "selected"}
		case "/orgs/owner/actions/runner-groups/50/repositories":
			body = map[string]any{"total_count": 1, "repositories": []any{fixtureRepository()}}
		case "/repos/owner/repo":
			body = fixtureRepository()
		case "/repos/owner/repo/actions/runs/60", "/repos/owner/repo/actions/runs/60/attempts/2":
			v := fixtureRun()
			v["status"] = "completed"
			v["conclusion"] = "success"
			if r.URL.Path == "/repos/owner/repo/actions/runs/60" {
				currentReads++
			}
			if mutation == "attempt" && currentReads > 1 {
				v["run_attempt"] = 3
			}
			body = v
		case "/repos/owner/repo/actions/runs/60/attempts/2/jobs":
			v := fixtureJob()
			v["status"] = "completed"
			v["conclusion"] = "success"
			if strings.HasPrefix(mutation, "conclusion-") {
				v["conclusion"] = strings.TrimPrefix(mutation, "conclusion-")
			}
			if mutation == "runner" {
				v["runner_id"] = 99
			}
			if mutation == "job" {
				v["id"] = 71
			}
			if mutation == "in-progress" {
				v["status"] = "in_progress"
			}
			jobs := []any{v}
			if mutation == "duplicate-owned" {
				other := fixtureJob()
				other["id"] = 71
				jobs = append(jobs, other)
			}
			body = map[string]any{"total_count": len(jobs), "jobs": jobs}
		case "/repos/owner/repo/contents/.github/workflows/ci.yml":
			body = fixtureContent()
		default:
			t.Error("unexpected completion route", r.URL.Path)
			w.WriteHeader(404)
			return
		}
		json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(s.Close)
	c, e := NewClient(s.URL, s.Client().Transport)
	if e != nil {
		t.Fatal(e)
	}
	return c, &calls
}
func TestObserveCompletedSuccess(t *testing.T) {
	for _, mutation := range []string{"none", "conclusion-failure", "conclusion-cancelled", "conclusion-skipped", "conclusion-neutral", "conclusion-timed_out", "attempt", "runner", "job", "in-progress", "duplicate-owned"} {
		t.Run(mutation, func(t *testing.T) {
			c, calls := completedFixture(t, mutation)
			v, _ := credentialref.NewValue([]byte("completion-read"))
			defer v.Close()
			checks := 0
			q := CompletedTarget{Target: fixtureTarget(), GroupName: "isolated", Check: func() error { checks++; return nil }}
			observed, e := c.ObserveCompletedSuccess(context.Background(), q, v)
			if mutation == "none" {
				if e != nil || observed.JobStatus != "completed" || observed.Binding.RunnerID != "40" {
					t.Fatal(observed, e)
				}
				if _, e = ci.Match(q.Target.Enrollment, observed, time.Now()); e == nil {
					t.Fatal("completed observation admitted as running")
				}
				if checks < *calls {
					t.Fatal("network request without current check", checks, *calls)
				}
			} else if e == nil || observed.RunID != "" {
				t.Fatal("non-success completion accepted", observed, e)
			}
		})
	}
}
func TestCompletedReadRevocationBeforeNetwork(t *testing.T) {
	c, calls := completedFixture(t, "none")
	v, _ := credentialref.NewValue([]byte("completion-read"))
	defer v.Close()
	_, e := c.ObserveCompletedSuccess(context.Background(), CompletedTarget{Target: fixtureTarget(), GroupName: "isolated", Check: func() error { return ErrIdentity }}, v)
	if e == nil || *calls != 0 {
		t.Fatal("revoked completion read", e, *calls)
	}
}
