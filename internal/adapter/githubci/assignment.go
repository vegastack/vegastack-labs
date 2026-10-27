package githubci

import (
	"context"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/ci"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
)

// AssignmentTarget must come from protected applied policy and the controller's
// independently owned runner receipt. Neither a name nor this read proves ownership.
type AssignmentTarget struct {
	Enrollment                             ci.Enrollment
	RunnerName, RunnerOS, GroupName, RunID string
	Attempt                                uint32
	Check                                  func() error
}

// FindAssignedJob discovers one numeric assignment and brackets the existing
// exact observation with current organization policy and owned-runner reads.
// Its result is inert: provider snapshots are non-atomic and grant no admission.
// The borrowed credential is never closed, discovered or minted here.
func (c *Client) FindAssignedJob(ctx context.Context, q AssignmentTarget, v *credentialref.Value) (ci.Observation, error) {
	empty := ci.Observation{}
	b := q.Enrollment.Binding
	org := OrganizationTarget{Login: strings.Split(b.Repository, "/")[0], ID: positiveID(b.OwnerID)}
	if !c.runnerValid(ctx, org, v, q.Check) || ci.ValidateEnrollment(q.Enrollment) != nil || !repositoryName.MatchString(b.Repository) || !workflowPath.MatchString(b.WorkflowPath) || strings.Contains(b.WorkflowPath, "..") || !runnerNameText(q.RunnerName, 128) || !runnerNameText(q.GroupName, 128) || (q.RunnerOS != "linux" && q.RunnerOS != "osx" && q.RunnerOS != "windows") || q.Attempt == 0 {
		return empty, ErrInput
	}
	for _, id := range []string{q.RunID, b.RunnerID, b.RunnerGroupID, b.RepositoryID, b.WorkflowID} {
		if positiveID(id) == 0 {
			return empty, ErrInput
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if e := c.assignmentOwner(ctx, q, org, v); e != nil {
		return empty, e
	}
	t := Target{Enrollment: q.Enrollment, RunID: q.RunID, Attempt: q.Attempt}
	current := "/repos/" + b.Repository + "/actions/runs/" + q.RunID
	readRun := func(path string) error {
		var r run
		if e := c.getChecked(ctx, path, v, &r, q.Check); e != nil {
			return e
		}
		if !r.matches(t) {
			return ErrIdentity
		}
		return nil
	}
	if e := readRun(current); e != nil {
		return empty, e
	}
	attempt := current + "/attempts/" + strconv.FormatUint(uint64(q.Attempt), 10)
	if e := readRun(attempt); e != nil {
		return empty, e
	}
	jobs, e := c.listJobs(ctx, attempt+"/jobs", t, v, q.Check)
	if e != nil {
		return empty, e
	}
	for _, j := range jobs {
		if j.RunnerID != positiveID(b.RunnerID) {
			continue
		}
		if t.JobID != "" {
			return empty, ErrIdentity
		}
		t.JobID = strconv.FormatInt(j.ID, 10)
		if !j.matches(t) {
			return empty, ErrIdentity
		}
	}
	if t.JobID == "" {
		return empty, ErrIdentity
	}
	observed, e := c.observe(ctx, t, v, q.Check)
	if e != nil {
		return empty, e
	}
	if e = c.assignmentOwner(ctx, q, org, v); e != nil {
		return empty, e
	}
	if e = readRun(current); e != nil {
		return empty, e
	}
	if _, e = ci.Match(q.Enrollment, observed, time.Now().UTC()); e != nil {
		return empty, ErrIdentity
	}
	if e = checked(ctx, q.Check); e != nil {
		return empty, e
	}
	return observed, nil
}

type assignmentRunner struct {
	ID     int64  `json:"id"`
	Name   string `json:"name"`
	OS     string `json:"os"`
	Status string `json:"status"`
	Busy   *bool  `json:"busy"`
	Labels []struct {
		Name string `json:"name"`
	} `json:"labels"`
}

func (r assignmentRunner) matches(q AssignmentTarget) bool {
	labels := make([]string, len(r.Labels))
	for i, l := range r.Labels {
		labels[i] = l.Name
	}
	slices.Sort(labels)
	expected := slices.Clone(q.Enrollment.Binding.Labels)
	slices.Sort(expected)
	return r.ID == positiveID(q.Enrollment.Binding.RunnerID) && r.Name == q.RunnerName && r.OS == q.RunnerOS && r.Status == "online" && r.Busy != nil && *r.Busy && slices.Equal(labels, expected)
}
func (c *Client) assignmentOwner(ctx context.Context, q AssignmentTarget, org OrganizationTarget, v *credentialref.Value) error {
	b := q.Enrollment.Binding
	registration := RunnerRegistrationRequest{Organization: org, Repository: b.Repository, RepositoryID: b.RepositoryID, RepositoryOwnerID: b.OwnerID, GroupName: q.GroupName, GroupID: positiveID(b.RunnerGroupID), Check: q.Check}
	if e := c.registrationPolicy(ctx, registration, v); e != nil {
		return e
	}
	var r assignmentRunner
	if e := c.getChecked(ctx, "/orgs/"+org.Login+"/actions/runners/"+b.RunnerID, v, &r, q.Check); e != nil {
		return e
	}
	if !r.matches(q) {
		return ErrIdentity
	}
	path := "/orgs/" + org.Login + "/actions/runner-groups/" + b.RunnerGroupID + "/runners"
	seen := map[int64]bool{}
	total := -1
	found := false
	for page := 1; page <= 10; page++ {
		var list struct {
			Count   *int               `json:"total_count"`
			Runners []assignmentRunner `json:"runners"`
		}
		if e := c.getChecked(ctx, path+"?page="+strconv.Itoa(page)+"&per_page=100", v, &list, q.Check); e != nil {
			return e
		}
		if list.Count == nil || *list.Count < 1 || *list.Count > 1000 {
			return ErrIdentity
		}
		if total < 0 {
			total = *list.Count
		}
		if total != *list.Count || len(list.Runners) != min(100, total-len(seen)) {
			return ErrIdentity
		}
		for _, r := range list.Runners {
			if r.ID <= 0 || seen[r.ID] {
				return ErrIdentity
			}
			seen[r.ID] = true
			if r.ID == positiveID(b.RunnerID) {
				if !r.matches(q) {
					return ErrIdentity
				}
				found = true
			}
		}
		if len(seen) == total {
			if !found {
				return ErrIdentity
			}
			return nil
		}
	}
	return ErrIdentity
}
