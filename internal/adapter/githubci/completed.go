package githubci

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/ci"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"strings"
	"time"
)

func (r run) matchesCompleted(t Target) bool {
	if r.Status != "completed" || r.Conclusion != "success" {
		return false
	}
	r.Status = "in_progress"
	return r.matches(t)
}
func (j job) matchesCompleted(t Target) bool {
	if j.Status != "completed" || j.Conclusion != "success" {
		return false
	}
	j.Status = "in_progress"
	return j.matches(t)
}

type CompletedTarget struct {
	Target    Target
	GroupName string
	Check     func() error
}

// ObserveCompletedSuccess is an inert terminal-success observation. It never
// changes Match's in-progress admission rules or revives a completed job lease.
// The exact old runner numeric identity is checked on the attempt's job record;
// a cleaned ephemeral runner need not still have a provider registration.
func (c *Client) ObserveCompletedSuccess(ctx context.Context, q CompletedTarget, v *credentialref.Value) (ci.Observation, error) {
	empty := ci.Observation{}
	b := q.Target.Enrollment.Binding
	org := OrganizationTarget{Login: strings.Split(b.Repository, "/")[0], ID: positiveID(b.OwnerID)}
	if !c.runnerValid(ctx, org, v, q.Check) || ci.ValidateEnrollment(q.Target.Enrollment) != nil || positiveID(q.Target.RunID) == 0 || positiveID(q.Target.JobID) == 0 || q.Target.Attempt == 0 || !runnerNameText(q.GroupName, 128) {
		return empty, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	policy := RunnerRegistrationRequest{Organization: org, Repository: b.Repository, RepositoryID: b.RepositoryID, RepositoryOwnerID: b.OwnerID, GroupID: positiveID(b.RunnerGroupID), GroupName: q.GroupName, Check: q.Check}
	if e := c.registrationPolicy(ctx, policy, v); e != nil {
		return empty, e
	}
	out, e := c.observeState(ctx, q.Target, v, q.Check, true)
	if e != nil {
		return empty, e
	}
	if e = c.registrationPolicy(ctx, policy, v); e != nil {
		return empty, e
	}
	if e = checked(ctx, q.Check); e != nil {
		return empty, e
	}
	return out, nil
}
