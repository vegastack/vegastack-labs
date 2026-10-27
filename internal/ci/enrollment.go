// Package ci compares explicit CI enrollments with fresh observations. A match
// describes identity equality only; it grants no execution or credential authority.
package ci

import (
	"path"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

const (
	// MaxObservationAge bounds how old a comparison's observation may be.
	MaxObservationAge = 60 * time.Second
	// MaxFutureSkew tolerates only a small positive observer clock difference.
	MaxFutureSkew = 5 * time.Second
)

// Binding contains exact source, workflow and assigned execution identities.
// Labels are an unordered set; all other fields compare byte for byte.
type Binding struct {
	RepositoryID, OwnerID, Repository, WorkflowID, WorkflowPath string
	WorkflowDigest, Revision, Ref, Event, JobName               string
	RunnerID, RunnerGroupID                                     string
	Labels                                                      []string
}

type PolicyBinding struct {
	RepositoryID, OwnerID, Repository, WorkflowID, WorkflowPath string
	WorkflowDigest, Revision, Ref, Event, JobName               string
	RunnerGroupID                                               string
	Labels                                                      []string
}

func ValidatePolicyBinding(p PolicyBinding) error {
	b := Binding{RepositoryID: p.RepositoryID, OwnerID: p.OwnerID, Repository: p.Repository, WorkflowID: p.WorkflowID, WorkflowPath: p.WorkflowPath, WorkflowDigest: p.WorkflowDigest, Revision: p.Revision, Ref: p.Ref, Event: p.Event, JobName: p.JobName, RunnerGroupID: p.RunnerGroupID, Labels: p.Labels}
	if !validPolicyBinding(b) {
		return failure.New(generated.ErrorCodeInputInvalid, "ci-enrollment", false)
	}
	return nil
}

type Enrollment struct {
	ID      string
	Binding Binding
}

// Observation must come from a trusted typed observer, never job-supplied claims.
// Provider reads remain a non-atomic snapshot; this type is not authorization.
type Observation struct {
	Binding                        Binding
	HeadRepositoryID, RunID, JobID string
	Attempt                        uint32
	RunStatus, JobStatus           string
	ObservedAt                     time.Time
}

// MatchResult is inert and must never be used as durable execution approval.
type MatchResult struct {
	Status, EnrollmentID, RunID, JobID string
	Attempt                            uint32
	ObservedAt                         time.Time
}

var (
	identifier     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
	repositoryPart = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
	digest         = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	revision       = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)
)

// ValidateEnrollment rejects missing, ambiguous and unbounded identities.
func ValidateEnrollment(e Enrollment) error {
	if !validID(e.ID) || !validBinding(e.Binding) {
		return failure.New(generated.ErrorCodeInputInvalid, "ci-enrollment", false)
	}
	return nil
}

// Match compares every bound field using caller-supplied current time. No
// normalization, caller input mutation, persistence or provider action occurs.
func Match(e Enrollment, o Observation, now time.Time) (MatchResult, error) {
	if err := ValidateEnrollment(e); err != nil {
		return MatchResult{}, err
	}
	if now.IsZero() {
		return MatchResult{}, failure.New(generated.ErrorCodeInputInvalid, "ci-enrollment", false)
	}
	if !validBinding(o.Binding) || !validID(o.HeadRepositoryID) || !validID(o.RunID) || !validID(o.JobID) ||
		o.HeadRepositoryID != e.Binding.RepositoryID || o.Attempt == 0 || o.RunStatus != "in_progress" || o.JobStatus != "in_progress" ||
		o.ObservedAt.IsZero() || now.Sub(o.ObservedAt) > MaxObservationAge || o.ObservedAt.Sub(now) > MaxFutureSkew || !equalBinding(e.Binding, o.Binding) {
		return MatchResult{}, failure.New(generated.ErrorCodeIntegrityFailure, "ci-enrollment", false)
	}
	return MatchResult{Status: "enrollment-match", EnrollmentID: e.ID, RunID: o.RunID, JobID: o.JobID, Attempt: o.Attempt, ObservedAt: o.ObservedAt}, nil
}

func validBinding(b Binding) bool { return validID(b.RunnerID) && validPolicyBinding(b) }

func validPolicyBinding(b Binding) bool {
	if !validID(b.RepositoryID) || !validID(b.OwnerID) || !validID(b.WorkflowID) || !validID(b.RunnerGroupID) ||
		!validRepository(b.Repository) || !validWorkflowPath(b.WorkflowPath) || !digest.MatchString(b.WorkflowDigest) || !revision.MatchString(b.Revision) ||
		!validRef(b.Ref) || (b.Event != "push" && b.Event != "workflow_dispatch") || !printable(b.JobName, 256) || strings.TrimSpace(b.JobName) == "" ||
		len(b.Labels) == 0 || len(b.Labels) > 64 {
		return false
	}
	seen := make(map[string]bool, len(b.Labels))
	for _, label := range b.Labels {
		if !validID(label) || seen[label] {
			return false
		}
		seen[label] = true
	}
	return true
}

func validID(s string) bool { return identifier.MatchString(s) }
func validRepository(s string) bool {
	if len(s) > 256 {
		return false
	}
	parts := strings.Split(s, "/")
	return len(parts) == 2 && repositoryPart.MatchString(parts[0]) && repositoryPart.MatchString(parts[1])
}
func printable(s string, max int) bool {
	if len(s) == 0 || len(s) > max {
		return false
	}
	for i := range len(s) {
		if s[i] < 32 || s[i] > 126 {
			return false
		}
	}
	return true
}
func validWorkflowPath(s string) bool {
	if !printable(s, 256) || strings.ContainsAny(s, `\:*?"<>|#%`) || strings.HasPrefix(s, "/") || path.Clean(s) != s {
		return false
	}
	for _, part := range strings.Split(s, "/") {
		if part == "." || part == ".." || part == "" || strings.TrimSpace(part) != part {
			return false
		}
	}
	return true
}
func validRef(s string) bool {
	if !printable(s, 256) || !strings.HasPrefix(s, "refs/heads/") || strings.ContainsAny(s, ` ~^:?*[\`) || strings.Contains(s, "..") || strings.Contains(s, "@{") {
		return false
	}
	branch := strings.TrimPrefix(s, "refs/heads/")
	for _, part := range strings.Split(branch, "/") {
		if part == "" || strings.HasPrefix(part, ".") || strings.HasSuffix(part, ".") || strings.HasSuffix(part, ".lock") {
			return false
		}
	}
	return true
}
func equalBinding(a, b Binding) bool {
	// Clones preserve the observer's and enrollment's label ordering.
	al, bl := slices.Clone(a.Labels), slices.Clone(b.Labels)
	slices.Sort(al)
	slices.Sort(bl)
	return a.RepositoryID == b.RepositoryID && a.OwnerID == b.OwnerID && a.Repository == b.Repository &&
		a.WorkflowID == b.WorkflowID && a.WorkflowPath == b.WorkflowPath && a.WorkflowDigest == b.WorkflowDigest &&
		a.Revision == b.Revision && a.Ref == b.Ref && a.Event == b.Event && a.JobName == b.JobName &&
		a.RunnerID == b.RunnerID && a.RunnerGroupID == b.RunnerGroupID && slices.Equal(al, bl)
}
