package ci

import (
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

func fixture() (Enrollment, Observation, time.Time) {
	now := time.Date(2026, 10, 27, 10, 0, 0, 0, time.UTC)
	e := Enrollment{ID: "enrollment-1", Binding: Binding{RepositoryID: "101", OwnerID: "owner-1", Repository: "owner/repo", WorkflowID: "workflow-1", WorkflowPath: ".github/workflows/check.yml", WorkflowDigest: "sha256:" + strings.Repeat("a", 64), Revision: strings.Repeat("b", 40), Ref: "refs/heads/main", Event: "push", JobName: "unit tests (linux)", RunnerID: "runner-1", RunnerGroupID: "group-1", Labels: []string{"linux", "isolated"}}}
	o := Observation{Binding: e.Binding, HeadRepositoryID: "101", RunID: "run-1", JobID: "job-1", Attempt: 1, RunStatus: "in_progress", JobStatus: "in_progress", ObservedAt: now}
	o.Binding.Labels = append([]string(nil), e.Binding.Labels...)
	return e, o, now
}

func TestMatchExactAndLabelSet(t *testing.T) {
	e, o, now := fixture()
	o.Binding.Labels = []string{"isolated", "linux"}
	before := append([]string(nil), o.Binding.Labels...)
	got, err := Match(e, o, now)
	want := MatchResult{Status: "enrollment-match", EnrollmentID: e.ID, RunID: o.RunID, JobID: o.JobID, Attempt: 1, ObservedAt: now}
	if err != nil || got != want {
		t.Fatalf("got %#v, %v", got, err)
	}
	if !reflect.DeepEqual(o.Binding.Labels, before) {
		t.Fatal("comparison mutated observation")
	}
	if err := ValidateEnrollment(e); err != nil {
		t.Fatal(err)
	}
}

func TestEveryBindingFieldMustMatch(t *testing.T) {
	e, _, _ := fixture()
	typ := reflect.TypeOf(e.Binding)
	for i := 0; i < typ.NumField(); i++ {
		name := typ.Field(i).Name
		t.Run(name, func(t *testing.T) {
			e, o, now := fixture()
			f := reflect.ValueOf(&o.Binding).Elem().FieldByName(name)
			if f.Kind() == reflect.Slice {
				f.Set(reflect.ValueOf([]string{"other"}))
			} else {
				replacement := map[string]string{"Repository": "owner/other", "WorkflowPath": "workflows/other.yml", "WorkflowDigest": "sha256:" + strings.Repeat("c", 64), "Revision": strings.Repeat("d", 40), "Ref": "refs/heads/other", "Event": "workflow_dispatch"}[name]
				if replacement == "" {
					replacement = "different"
				}
				f.SetString(replacement)
			}
			assertDenied(t, e, o, now, generated.ErrorCodeIntegrityFailure)
		})
	}
}

func TestInvalidEnrollment(t *testing.T) {
	tests := map[string]func(*Enrollment){
		"missing enrollment":       func(e *Enrollment) { e.ID = "" },
		"unsafe ID":                func(e *Enrollment) { e.Binding.OwnerID = "../secret" },
		"long ID":                  func(e *Enrollment) { e.Binding.RunnerID = strings.Repeat("a", 129) },
		"repository missing owner": func(e *Enrollment) { e.Binding.Repository = "repo" },
		"repository traversal":     func(e *Enrollment) { e.Binding.Repository = "../repo" },
		"repository extra slash":   func(e *Enrollment) { e.Binding.Repository = "owner/repo/sub" },
		"absolute workflow":        func(e *Enrollment) { e.Binding.WorkflowPath = "/workflow.yml" },
		"traversal workflow":       func(e *Enrollment) { e.Binding.WorkflowPath = "foo/../workflow.yml" },
		"unclean workflow":         func(e *Enrollment) { e.Binding.WorkflowPath = "foo//workflow.yml" },
		"backslash workflow":       func(e *Enrollment) { e.Binding.WorkflowPath = `foo\workflow.yml` },
		"long workflow":            func(e *Enrollment) { e.Binding.WorkflowPath = strings.Repeat("a", 257) },
		"upper digest":             func(e *Enrollment) { e.Binding.WorkflowDigest = "sha256:" + strings.Repeat("A", 64) },
		"short digest":             func(e *Enrollment) { e.Binding.WorkflowDigest = "sha256:" + strings.Repeat("a", 63) },
		"bad revision":             func(e *Enrollment) { e.Binding.Revision = strings.Repeat("g", 40) },
		"short revision":           func(e *Enrollment) { e.Binding.Revision = strings.Repeat("b", 39) },
		"tag ref":                  func(e *Enrollment) { e.Binding.Ref = "refs/tags/main" },
		"wildcard ref":             func(e *Enrollment) { e.Binding.Ref = "refs/heads/*" },
		"empty ref":                func(e *Enrollment) { e.Binding.Ref = "refs/heads/" },
		"ref traversal":            func(e *Enrollment) { e.Binding.Ref = "refs/heads/a/../b" },
		"ref lock":                 func(e *Enrollment) { e.Binding.Ref = "refs/heads/main.lock" },
		"ref control":              func(e *Enrollment) { e.Binding.Ref = "refs/heads/main\n" },
		"PR":                       func(e *Enrollment) { e.Binding.Event = "pull_request" },
		"PR target":                func(e *Enrollment) { e.Binding.Event = "pull_request_target" },
		"unknown event":            func(e *Enrollment) { e.Binding.Event = "schedule" },
		"job control":              func(e *Enrollment) { e.Binding.JobName = "test\n" },
		"long job":                 func(e *Enrollment) { e.Binding.JobName = strings.Repeat("a", 257) },
		"empty labels":             func(e *Enrollment) { e.Binding.Labels = nil },
		"duplicate labels":         func(e *Enrollment) { e.Binding.Labels = []string{"linux", "linux"} },
		"unsafe label":             func(e *Enrollment) { e.Binding.Labels = []string{"linux\n"} },
		"many labels":              func(e *Enrollment) { e.Binding.Labels = make([]string, 65) },
	}
	// Every required binding string must be present.
	e, _, _ := fixture()
	typ := reflect.TypeOf(e.Binding)
	for i := 0; i < typ.NumField(); i++ {
		if typ.Field(i).Type.Kind() == reflect.String {
			name := typ.Field(i).Name
			tests["empty "+name] = func(e *Enrollment) { reflect.ValueOf(&e.Binding).Elem().FieldByName(name).SetString("") }
		}
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			e, _, _ := fixture()
			mutate(&e)
			err := ValidateEnrollment(e)
			assertCode(t, err, generated.ErrorCodeInputInvalid)
		})
	}
}

func TestObservationDenials(t *testing.T) {
	tests := map[string]func(*Observation){
		"fork":                      func(o *Observation) { o.HeadRepositoryID = "another" },
		"missing head":              func(o *Observation) { o.HeadRepositoryID = "" },
		"missing run":               func(o *Observation) { o.RunID = "" },
		"unsafe run":                func(o *Observation) { o.RunID = "../secret" },
		"missing job":               func(o *Observation) { o.JobID = "" },
		"zero attempt":              func(o *Observation) { o.Attempt = 0 },
		"queued run":                func(o *Observation) { o.RunStatus = "queued" },
		"completed run":             func(o *Observation) { o.RunStatus = "completed" },
		"queued job":                func(o *Observation) { o.JobStatus = "queued" },
		"completed job":             func(o *Observation) { o.JobStatus = "completed" },
		"zero timestamp":            func(o *Observation) { o.ObservedAt = time.Time{} },
		"stale":                     func(o *Observation) { o.ObservedAt = o.ObservedAt.Add(-60*time.Second - time.Nanosecond) },
		"future":                    func(o *Observation) { o.ObservedAt = o.ObservedAt.Add(5*time.Second + time.Nanosecond) },
		"duplicate observed labels": func(o *Observation) { o.Binding.Labels = []string{"linux", "linux"} },
		"case identity":             func(o *Observation) { o.Binding.Repository = "Owner/repo" },
		"case label":                func(o *Observation) { o.Binding.Labels = []string{"Linux", "isolated"} },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			e, o, now := fixture()
			mutate(&o)
			assertDenied(t, e, o, now, generated.ErrorCodeIntegrityFailure)
		})
	}
	e, o, _ := fixture()
	assertDenied(t, e, o, time.Time{}, generated.ErrorCodeInputInvalid)
	e.ID = "secret\nraw"
	assertDenied(t, e, o, o.ObservedAt, generated.ErrorCodeInputInvalid)
}

func TestAcceptedBoundaries(t *testing.T) {
	for _, age := range []time.Duration{-5 * time.Second, 0, 60 * time.Second} {
		e, o, now := fixture()
		o.ObservedAt = now.Add(-age)
		if _, err := Match(e, o, now); err != nil {
			t.Fatalf("age %v: %v", age, err)
		}
	}
	e, o, now := fixture()
	e.Binding.WorkflowPath = "workflow.yml"
	e.Binding.Revision = strings.Repeat("c", 64)
	e.Binding.Event = "workflow_dispatch"
	e.Binding.RunnerID = strings.Repeat("r", 128)
	e.Binding.JobName = strings.Repeat("j", 256)
	o.Binding = e.Binding
	if _, err := Match(e, o, now); err != nil {
		t.Fatal(err)
	}
}

func TestCollectionAndStringBounds(t *testing.T) {
	e, _, _ := fixture()
	e.Binding.Labels = make([]string, 64)
	for i := range e.Binding.Labels {
		e.Binding.Labels[i] = "label-" + strconv.Itoa(i)
	}
	e.Binding.Labels[0] = strings.Repeat("a", 128)
	e.Binding.WorkflowPath = strings.Repeat("a", 256)
	e.Binding.Ref = "refs/heads/" + strings.Repeat("b", 245)
	e.Binding.Repository = strings.Repeat("o", 127) + "/" + strings.Repeat("r", 128)
	if err := ValidateEnrollment(e); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*Enrollment){
		"label count":       func(e *Enrollment) { e.Binding.Labels = append(e.Binding.Labels, "extra") },
		"label length":      func(e *Enrollment) { e.Binding.Labels[0] += "a" },
		"ref length":        func(e *Enrollment) { e.Binding.Ref += "b" },
		"repository length": func(e *Enrollment) { e.Binding.Repository += "r" },
		"workflow length":   func(e *Enrollment) { e.Binding.WorkflowPath += "a" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			copy := e
			copy.Binding.Labels = append([]string(nil), e.Binding.Labels...)
			mutate(&copy)
			assertCode(t, ValidateEnrollment(copy), generated.ErrorCodeInputInvalid)
		})
	}
}

func assertDenied(t *testing.T, e Enrollment, o Observation, now time.Time, code string) {
	t.Helper()
	got, err := Match(e, o, now)
	assertCode(t, err, code)
	if got != (MatchResult{}) {
		t.Fatal("denial returned match data")
	}
}
func assertCode(t *testing.T, err error, code string) {
	t.Helper()
	if err == nil {
		t.Fatal("accepted invalid input")
	}
	f, ok := failure.As(err)
	if !ok || f.Code != code {
		t.Fatalf("unexpected error %v", err)
	}
	if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "\n") {
		t.Fatal("error leaked raw input")
	}
}

func TestPolicyBindingDoesNotRequireTransientRunner(t *testing.T) {
	e, _, _ := fixture()
	b := e.Binding
	p := PolicyBinding{RepositoryID: b.RepositoryID, OwnerID: b.OwnerID, Repository: b.Repository, WorkflowID: b.WorkflowID, WorkflowPath: b.WorkflowPath, WorkflowDigest: b.WorkflowDigest, Revision: b.Revision, Ref: b.Ref, Event: b.Event, JobName: b.JobName, RunnerGroupID: b.RunnerGroupID, Labels: b.Labels}
	if err := ValidatePolicyBinding(p); err != nil {
		t.Fatal(err)
	}
	e.Binding.RunnerID = ""
	if ValidateEnrollment(e) == nil {
		t.Fatal("assigned runner is still required")
	}
}
