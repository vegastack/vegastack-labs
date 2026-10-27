package githubci

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/strictjson"
)

type OrganizationTarget struct {
	Login string
	ID    int64
}

// Check must revalidate current caller authority and journal mutation intent.
// It is called before every request and immediately before token consumption.
type RunnerRegistrationRequest struct {
	Organization                                           OrganizationTarget
	Repository, RepositoryID, RepositoryOwnerID, GroupName string
	GroupID                                                int64
	Check                                                  func() error
}
type RegistrationConsumer func(context.Context, *credentialref.Value, time.Time) error

// An attempted stage must be retained even if a request or consumer fails.
// Consumed proves only synchronous token delivery, never runner admission.
type RegistrationReceipt struct {
	Stage     string
	ExpiresAt time.Time
}
type RunnerCleanupRequest struct {
	Organization OrganizationTarget
	RunnerID     int64
	Name, OS     string
	Labels       []string
	Check        func() error
}
type RunnerCleanupReceipt struct {
	Stage  string
	Absent bool
}

var organizationLogin = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,38}$`)

func validOrganization(o OrganizationTarget) bool {
	return o.ID > 0 && organizationLogin.MatchString(o.Login)
}
func runnerText(s string, max int) bool {
	if len(s) == 0 || len(s) > max || strings.TrimSpace(s) != s {
		return false
	}
	for i := range len(s) {
		if s[i] < 33 || s[i] > 126 {
			return false
		}
	}
	return true
}

// Provider names and labels may contain interior spaces; routes never use them.
func runnerNameText(s string, max int) bool {
	if len(s) == 0 || len(s) > max || strings.TrimSpace(s) != s {
		return false
	}
	for i := range len(s) {
		if s[i] < 32 || s[i] > 126 {
			return false
		}
	}
	return true
}
func runnerCredential(v *credentialref.Value) bool {
	if v == nil || len(v.Bytes()) > 4096 {
		return false
	}
	return runnerText(string(v.Bytes()), 4096)
}
func (c *Client) runnerValid(ctx context.Context, o OrganizationTarget, v *credentialref.Value, check func() error) bool {
	return ctx != nil && c != nil && c.http != nil && validOrganization(o) && runnerCredential(v) && check != nil
}
func checked(ctx context.Context, check func() error) error {
	if ctx.Err() != nil {
		return ErrUnavailable
	}
	if check() == nil && ctx.Err() == nil {
		return nil
	}
	return failure.New(generated.ErrorCodeAuthorizationDenied, "github-ci-runner", false)
}
func (c *Client) organization(ctx context.Context, o OrganizationTarget, v *credentialref.Value, check func() error) error {
	var got struct {
		ID    int64  `json:"id"`
		Login string `json:"login"`
	}
	if _, e := c.runnerRequest(ctx, http.MethodGet, "/orgs/"+o.Login, v, check, &got, nil); e != nil {
		return e
	}
	if got.ID != o.ID || got.Login != o.Login {
		return ErrIdentity
	}
	return nil
}

// PrepareRegistration verifies organization, repository and selected-group access
// before requesting a transient organization token. Tokens are delivered only
// within the synchronous consumer and are closed on success, error or panic.
func (c *Client) PrepareRegistration(ctx context.Context, q RunnerRegistrationRequest, v *credentialref.Value, consume RegistrationConsumer) (RegistrationReceipt, error) {
	out := RegistrationReceipt{}
	if !c.runnerValid(ctx, q.Organization, v, q.Check) || consume == nil || !repositoryName.MatchString(q.Repository) || positiveID(q.RepositoryID) == 0 || positiveID(q.RepositoryOwnerID) != q.Organization.ID || strings.Split(q.Repository, "/")[0] != q.Organization.Login || q.GroupID <= 0 || !runnerNameText(q.GroupName, 128) {
		return out, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if e := c.registrationPolicy(ctx, q, v); e != nil {
		return out, e
	}
	// The callback runs before the request; only actual dispatch sets attempted.
	var token struct {
		Token     string `json:"token"`
		ExpiresAt string `json:"expires_at"`
	}
	_, e := c.runnerRequest(ctx, http.MethodPost, "/orgs/"+q.Organization.Login+"/actions/runners/registration-token", v, q.Check, &token, func() { out.Stage = "token-request-attempted" })
	if e != nil {
		return out, e
	}
	expiry, e := time.Parse(time.RFC3339, token.ExpiresAt)
	now := time.Now()
	if e != nil || !expiry.After(now) || expiry.After(now.Add(65*time.Minute)) || !runnerText(token.Token, 4096) {
		token.Token = ""
		return out, ErrIdentity
	}
	tokenBytes := []byte(token.Token)
	value, e := credentialref.NewValue(tokenBytes)
	for i := range tokenBytes {
		tokenBytes[i] = 0
	}
	token.Token = ""
	if e != nil {
		return out, ErrIdentity
	}
	defer value.Close()
	out.ExpiresAt = expiry
	if e := checked(ctx, q.Check); e != nil {
		return out, e
	}
	if !expiry.After(time.Now()) {
		return out, ErrIdentity
	}
	if e := consume(ctx, value, expiry); e != nil {
		return out, ErrUnavailable
	}
	if ctx.Err() != nil {
		return out, ErrUnavailable
	}
	out.Stage = "consumed"
	return out, nil
}
func (c *Client) registrationPolicy(ctx context.Context, q RunnerRegistrationRequest, v *credentialref.Value) error {
	if e := c.organization(ctx, q.Organization, v, q.Check); e != nil {
		return e
	}
	var repo repository
	if _, e := c.runnerRequest(ctx, http.MethodGet, "/repos/"+q.Repository, v, q.Check, &repo, nil); e != nil {
		return e
	}
	if !registrationRepository(repo, q) {
		return ErrIdentity
	}
	groupPath := "/orgs/" + q.Organization.Login + "/actions/runner-groups/" + strconv.FormatInt(q.GroupID, 10)
	var group struct {
		ID         int64  `json:"id"`
		Name       string `json:"name"`
		Visibility string `json:"visibility"`
	}
	if _, e := c.runnerRequest(ctx, http.MethodGet, groupPath, v, q.Check, &group, nil); e != nil {
		return e
	}
	if group.ID != q.GroupID || group.Name != q.GroupName || group.Visibility != "selected" {
		return ErrIdentity
	}
	if e := c.selectedRepository(ctx, groupPath+"/repositories", q, v); e != nil {
		return e
	}
	return nil
}
func registrationRepository(r repository, q RunnerRegistrationRequest) bool {
	return r.ID == positiveID(q.RepositoryID) && r.Owner.ID == q.Organization.ID && r.Owner.Login == q.Organization.Login && r.FullName == q.Repository && r.Name == strings.Split(q.Repository, "/")[1]
}
func (c *Client) selectedRepository(ctx context.Context, path string, q RunnerRegistrationRequest, v *credentialref.Value) error {
	total := -1
	found := false
	seen := map[int64]bool{}
	for page := 1; page <= 10; page++ {
		var list struct {
			Count        *int         `json:"total_count"`
			Repositories []repository `json:"repositories"`
		}
		if _, e := c.runnerRequest(ctx, http.MethodGet, path+"?page="+strconv.Itoa(page)+"&per_page=100", v, q.Check, &list, nil); e != nil {
			return e
		}
		if list.Count == nil || *list.Count < 1 || *list.Count > 1000 {
			return ErrIdentity
		}
		if total < 0 {
			total = *list.Count
		}
		if total != *list.Count || len(list.Repositories) != min(100, total-len(seen)) {
			return ErrIdentity
		}
		for _, r := range list.Repositories {
			if r.ID <= 0 || seen[r.ID] {
				return ErrIdentity
			}
			seen[r.ID] = true
			if r.ID == positiveID(q.RepositoryID) {
				if !registrationRepository(r, q) {
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

// RemoveOwnedRunner requires the caller to stop its one-job process first. A
// GET/DELETE pair cannot enforce atomic provider state; offline/idle observations
// and current checks never substitute for controller ownership or isolation.
func (c *Client) RemoveOwnedRunner(ctx context.Context, q RunnerCleanupRequest, v *credentialref.Value) (RunnerCleanupReceipt, error) {
	out := RunnerCleanupReceipt{}
	if !c.runnerValid(ctx, q.Organization, v, q.Check) || q.RunnerID <= 0 || !runnerNameText(q.Name, 128) || (q.OS != "linux" && q.OS != "osx" && q.OS != "windows") || len(q.Labels) == 0 || len(q.Labels) > 64 {
		return out, ErrInput
	}
	expected := slices.Clone(q.Labels)
	slices.Sort(expected)
	for i, s := range expected {
		if !runnerNameText(s, 128) || (i > 0 && s == expected[i-1]) {
			return out, ErrInput
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if e := c.organization(ctx, q.Organization, v, q.Check); e != nil {
		return out, e
	}
	path := "/orgs/" + q.Organization.Login + "/actions/runners/" + strconv.FormatInt(q.RunnerID, 10)
	var runner struct {
		ID     int64  `json:"id"`
		Name   string `json:"name"`
		OS     string `json:"os"`
		Status string `json:"status"`
		Busy   *bool  `json:"busy"`
		Labels []struct {
			Name string `json:"name"`
		} `json:"labels"`
	}
	status, e := c.runnerRequest(ctx, http.MethodGet, path, v, q.Check, &runner, nil)
	if status == 404 {
		out.Stage = "absent"
		out.Absent = true
		return out, nil
	}
	if e != nil {
		return out, e
	}
	labels := make([]string, len(runner.Labels))
	for i, l := range runner.Labels {
		labels[i] = l.Name
	}
	slices.Sort(labels)
	if runner.ID != q.RunnerID || runner.Name != q.Name || runner.OS != q.OS || runner.Status != "offline" || runner.Busy == nil || *runner.Busy || !slices.Equal(labels, expected) {
		return out, ErrIdentity
	}
	_, e = c.runnerRequest(ctx, http.MethodDelete, path, v, q.Check, nil, func() { out.Stage = "delete-attempted" })
	if e != nil {
		return out, e
	}
	out.Stage = "deleted"
	return out, nil
}

// runnerRequest never follows provider URLs, retries or exposes provider errors.
// The mutation marker runs after the last authority check, before dispatch.
func (c *Client) runnerRequest(ctx context.Context, method, path string, v *credentialref.Value, check func() error, out any, attempt func()) (int, error) {
	req, e := http.NewRequestWithContext(ctx, method, c.base+path, nil)
	if e != nil {
		return 0, ErrInput
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("Authorization", "Bearer "+string(v.Bytes()))
	if e := checked(ctx, check); e != nil {
		return 0, e
	}
	if attempt != nil {
		attempt()
	}
	res, e := c.http.Do(req)
	if e != nil {
		return 0, ErrUnavailable
	}
	defer res.Body.Close()
	want := 200
	if method == http.MethodPost {
		want = 201
	}
	if method == http.MethodDelete {
		want = 204
	}
	if res.StatusCode != want {
		code := generated.ErrorCodeDependencyUnavailable
		switch res.StatusCode {
		case 401:
			code = generated.ErrorCodeAuthenticationRequired
		case 403:
			code = generated.ErrorCodeAuthorizationDenied
		case 404:
			code = generated.ErrorCodeResourceNotFound
		case 429:
			code = generated.ErrorCodeRateLimited
		}
		return res.StatusCode, failure.New(code, "github-ci-runner", false)
	}
	if out == nil {
		return res.StatusCode, nil
	}
	raw, e := io.ReadAll(io.LimitReader(res.Body, maxBody+1))
	defer func() {
		for i := range raw {
			raw[i] = 0
		}
	}()
	if e != nil {
		return res.StatusCode, ErrUnavailable
	}
	trimmed := strings.TrimSpace(string(raw))
	if len(raw) > maxBody || len(trimmed) == 0 || trimmed[0] != '{' || strictjson.Scan(ctx, raw, strictjson.Limits{MaxDepth: 32}) != nil || json.Unmarshal(raw, out) != nil {
		return res.StatusCode, ErrIdentity
	}
	return res.StatusCode, nil
}
