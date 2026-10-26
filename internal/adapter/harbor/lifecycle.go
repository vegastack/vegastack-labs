package harbor

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Access struct {
	Resource string `json:"resource"`
	Action   string `json:"action"`
	Effect   string `json:"effect"`
}
type RobotPermission struct {
	Kind      string   `json:"kind"`
	Namespace string   `json:"namespace"`
	Access    []Access `json:"access"`
}
type RobotBinding struct {
	ID              int64  `json:"id"`
	Name            string `json:"name"`
	ReferenceID     string `json:"referenceId"`
	MaterialVersion string `json:"materialVersion"`
	Push            bool   `json:"push"`
	Duration        int64  `json:"duration"`
}
type ProjectBinding struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Public      bool   `json:"public"`
	RetentionID int64  `json:"retentionId"`
	KeepLast    int64  `json:"keepLast"`
}
type LifecycleRequest struct {
	Projects []ProjectBinding `json:"projects"`
	Robots   []RobotBinding   `json:"robots"`
	Check    func() error     `json:"-"`
}
type LifecycleSnapshot struct {
	Projects []ProjectBinding `json:"projects"`
	Robots   []RobotBinding   `json:"robots"`
}

// SecretSink must atomically stage the one-time secret into the existing
// protected credential import mechanism before returning. No plaintext escapes.
type SecretSink func(context.Context, RobotBinding, io.Reader) error
type SecretSource func(context.Context, RobotBinding) (*credentialref.Value, error)

func (c *Client) lifecycleRequest(ctx context.Context, method, path string, in, out any, user string, v *credentialref.Value, check func() error) (int, error) {
	if c == nil || c.http == nil || ctx == nil || check == nil || user == "" || strings.ContainsAny(user, ":\r\n\x00") || len(v.Bytes()) == 0 || bytes.ContainsAny(v.Bytes(), "\r\n\x00") {
		return 0, clientError("INPUT_INVALID")
	}
	if e := check(); e != nil {
		return 0, e
	}
	var payload []byte
	var e error
	if in != nil {
		payload, e = json.Marshal(in)
		if e != nil {
			return 0, clientError("INPUT_INVALID")
		}
	}
	req, e := http.NewRequestWithContext(ctx, method, c.origin+"/api/v2.0"+path, bytes.NewReader(payload))
	if e != nil {
		return 0, clientError("INPUT_INVALID")
	}
	req.SetBasicAuth(user, string(v.Bytes()))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	res, e := c.http.Do(req)
	if e != nil {
		return 0, clientError("DEPENDENCY_UNAVAILABLE")
	}
	defer res.Body.Close()
	if res.StatusCode == 404 && method == "GET" {
		return 404, check()
	}
	if res.StatusCode != 200 && res.StatusCode != 201 && res.StatusCode != 204 {
		return res.StatusCode, clientError("DEPENDENCY_UNAVAILABLE")
	}
	b, e := io.ReadAll(io.LimitReader(res.Body, maxBody+1))
	if e != nil || len(b) > maxBody {
		return res.StatusCode, clientError("INTEGRITY_FAILURE")
	}
	defer func() {
		for i := range b {
			b[i] = 0
		}
	}()
	if len(bytes.TrimSpace(b)) == 0 && out == nil {
		return res.StatusCode, check()
	}
	if !validJSON(b) || out == nil || json.Unmarshal(b, out) != nil {
		return res.StatusCode, clientError("INTEGRITY_FAILURE")
	}
	return res.StatusCode, check()
}
func validateLifecycle(q LifecycleRequest) bool {
	if q.Check == nil || len(q.Projects) == 0 || len(q.Projects) > 128 || len(q.Robots) != 2 {
		return false
	}
	seen := map[string]bool{}
	for _, p := range q.Projects {
		if !componentPattern.MatchString(p.Name) || p.ID < 0 || p.RetentionID < 0 || p.KeepLast < 1 || p.KeepLast > 100000 || seen[p.Name] {
			return false
		}
		seen[p.Name] = true
	}
	pushes := 0
	names := map[string]bool{}
	for _, r := range q.Robots {
		if r.ID < 0 || !strings.HasPrefix(r.Name, "robot$") || len(r.Name) > 128 || strings.ContainsAny(r.Name, " /\r\n\\\x00") || r.Duration < 1 || r.Duration > 365 || names[r.Name] {
			return false
		}
		if _, e := credentialref.ParseID(r.ReferenceID); e != nil {
			return false
		}
		if _, e := credentialref.ParseID(r.MaterialVersion); e != nil {
			return false
		}
		names[r.Name] = true
		if r.Push {
			pushes++
		}
	}
	return pushes == 1
}
func permissions(q LifecycleRequest, push bool) []RobotPermission {
	out := make([]RobotPermission, 0, len(q.Projects))
	for _, p := range q.Projects {
		a := []Access{{"repository", "pull", "allow"}}
		if push {
			a = append(a, Access{"repository", "push", "allow"})
		}
		out = append(out, RobotPermission{"project", p.Name, a})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Namespace < out[j].Namespace })
	return out
}
func permissionEqual(a, b []RobotPermission) bool {
	normal := func(p []RobotPermission) string {
		p = append([]RobotPermission(nil), p...)
		for i := range p {
			p[i].Access = append([]Access(nil), p[i].Access...)
			sort.Slice(p[i].Access, func(a, b int) bool { return p[i].Access[a].Action < p[i].Access[b].Action })
		}
		sort.Slice(p, func(i, j int) bool { return p[i].Namespace < p[j].Namespace })
		x, _ := json.Marshal(p)
		return string(x)
	}
	return normal(a) == normal(b)
}
func (c *Client) ObserveLifecycle(ctx context.Context, q LifecycleRequest, user string, v *credentialref.Value) (LifecycleSnapshot, error) {
	var out LifecycleSnapshot
	if !validateLifecycle(q) {
		return out, clientError("INPUT_INVALID")
	}
	for _, p := range q.Projects {
		var got struct {
			ID       int64             `json:"project_id"`
			Name     string            `json:"name"`
			Metadata map[string]string `json:"metadata"`
		}
		status, e := c.lifecycleRequest(ctx, "GET", "/projects/"+p.Name, nil, &got, user, v, q.Check)
		if e != nil {
			return out, e
		}
		if status == 404 {
			if p.ID != 0 {
				return out, clientError("INTEGRITY_FAILURE")
			}
			continue
		}
		if p.ID == 0 || p.ID != got.ID || p.Name != got.Name {
			return out, clientError("INTEGRITY_FAILURE")
		}
		if got.Metadata["public"] != strconv.FormatBool(p.Public) {
			return out, clientError("INTEGRITY_FAILURE")
		}
		out.Projects = append(out.Projects, p)
		if p.RetentionID > 0 {
			var rp retentionPolicy
			_, e = c.lifecycleRequest(ctx, "GET", "/retentions/"+strconv.FormatInt(p.RetentionID, 10), nil, &rp, user, v, q.Check)
			if e != nil {
				return out, e
			}
			if rp.ID != p.RetentionID || !equalRetention(rp, retention(p)) {
				return out, clientError("INTEGRITY_FAILURE")
			}
		}
	}
	for _, r := range q.Robots {
		if r.ID == 0 {
			continue
		}
		var got struct {
			ID          int64             `json:"id"`
			Name        string            `json:"name"`
			Level       string            `json:"level"`
			Disable     bool              `json:"disable"`
			Expires     int64             `json:"expires_at"`
			Permissions []RobotPermission `json:"permissions"`
		}
		_, e := c.lifecycleRequest(ctx, "GET", "/robots/"+strconv.FormatInt(r.ID, 10), nil, &got, user, v, q.Check)
		if e != nil {
			return out, e
		}
		if got.ID != r.ID || got.Name != r.Name || got.Level != "system" || got.Disable || got.Expires <= time.Now().Unix() || !permissionEqual(got.Permissions, permissions(q, r.Push)) {
			return out, clientError("INTEGRITY_FAILURE")
		}
		out.Robots = append(out.Robots, r)
	}
	return out, nil
}

type retentionSelector struct {
	Kind       string `json:"kind"`
	Decoration string `json:"decoration"`
	Pattern    string `json:"pattern"`
}
type retentionRule struct {
	ID             int64                          `json:"id,omitempty"`
	Priority       int64                          `json:"priority"`
	Disabled       bool                           `json:"disabled"`
	Action         string                         `json:"action"`
	Template       string                         `json:"template"`
	Params         map[string]int64               `json:"params"`
	TagSelectors   []retentionSelector            `json:"tag_selectors"`
	ScopeSelectors map[string][]retentionSelector `json:"scope_selectors"`
}
type retentionPolicy struct {
	ID        int64           `json:"id,omitempty"`
	Algorithm string          `json:"algorithm"`
	Rules     []retentionRule `json:"rules"`
	Trigger   struct {
		Kind string `json:"kind"`
	} `json:"trigger"`
	Scope struct {
		Level string `json:"level"`
		Ref   int64  `json:"ref"`
	} `json:"scope"`
}

func retention(p ProjectBinding) retentionPolicy {
	var out retentionPolicy
	out.ID = p.RetentionID
	out.Algorithm = "or"
	out.Trigger.Kind = "Manual"
	out.Scope.Level = "project"
	out.Scope.Ref = p.ID
	selectors := map[string][]retentionSelector{"repository": {{"doublestar", "repoMatches", "**"}}}
	out.Rules = []retentionRule{{Priority: 0, Action: "retain", Template: "latestPushedK", Params: map[string]int64{"latestPushedK": p.KeepLast}, TagSelectors: []retentionSelector{{"doublestar", "matches", "**"}}, ScopeSelectors: selectors}, {Priority: 1, Action: "retain", Template: "always", Params: map[string]int64{}, TagSelectors: []retentionSelector{{"doublestar", "matches", "vsk-recovery-**"}}, ScopeSelectors: selectors}}
	return out
}
func equalRetention(a, b retentionPolicy) bool {
	a.ID = 0
	b.ID = 0
	for i := range a.Rules {
		a.Rules[i].ID = 0
	}
	for i := range b.Rules {
		b.Rules[i].ID = 0
	}
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}

// ApplyLifecycle configures retention only; it never triggers deletion or GC.
// No create/update is retried; caller must journal the attempt before calling.
func (c *Client) ApplyLifecycle(ctx context.Context, q LifecycleRequest, user string, v *credentialref.Value, sink SecretSink) (LifecycleSnapshot, error) {
	return c.applyLifecycle(ctx, q, user, v, sink, nil)
}
func (c *Client) ApplyLifecycleWithSecrets(ctx context.Context, q LifecycleRequest, user string, v *credentialref.Value, source SecretSource) (LifecycleSnapshot, error) {
	if source == nil {
		return LifecycleSnapshot{}, clientError("PREREQUISITE_BLOCKED")
	}
	return c.applyLifecycle(ctx, q, user, v, nil, source)
}
func (c *Client) applyLifecycle(ctx context.Context, q LifecycleRequest, user string, v *credentialref.Value, sink SecretSink, source SecretSource) (LifecycleSnapshot, error) {
	out, e := c.ObserveLifecycle(ctx, q, user, v)
	if e != nil {
		return out, e
	}
	for _, r := range q.Robots {
		if r.ID == 0 && sink == nil && source == nil {
			return out, clientError("PREREQUISITE_BLOCKED")
		}
	}
	for i, p := range q.Projects {
		if p.ID == 0 {
			body := struct {
				Name     string            `json:"project_name"`
				Metadata map[string]string `json:"metadata"`
			}{p.Name, map[string]string{"public": strconv.FormatBool(p.Public), "auto_scan": "true"}}
			if _, e = c.lifecycleRequest(ctx, "POST", "/projects", body, nil, user, v, q.Check); e != nil {
				return out, e
			}
			var got struct {
				ID   int64  `json:"project_id"`
				Name string `json:"name"`
			}
			if _, e = c.lifecycleRequest(ctx, "GET", "/projects/"+p.Name, nil, &got, user, v, q.Check); e != nil || got.ID <= 0 || got.Name != p.Name {
				return out, clientError("INTEGRITY_FAILURE")
			}
			p.ID = got.ID
			q.Projects[i].ID = got.ID
		}
		if p.RetentionID == 0 {
			if _, e = c.lifecycleRequest(ctx, "POST", "/retentions", retention(p), nil, user, v, q.Check); e != nil {
				return out, e
			}
			var got struct {
				Metadata map[string]string `json:"metadata"`
			}
			if _, e = c.lifecycleRequest(ctx, "GET", "/projects/"+p.Name, nil, &got, user, v, q.Check); e != nil {
				return out, e
			}
			id, er := strconv.ParseInt(got.Metadata["retention_id"], 10, 64)
			if er != nil || id <= 0 {
				return out, clientError("INTEGRITY_FAILURE")
			}
			q.Projects[i].RetentionID = id
		}
	}
	for i, r := range q.Robots {
		if r.ID != 0 {
			continue
		}
		var got struct {
			ID     int64  `json:"id"`
			Name   string `json:"name"`
			Secret string `json:"secret"`
		}
		var material *credentialref.Value
		if source != nil {
			material, e = source(ctx, r)
			if e != nil {
				return out, e
			}
			if material == nil || len(material.Bytes()) < 8 || len(material.Bytes()) > 4096 {
				return out, clientError("INPUT_INVALID")
			}
			defer material.Close()
		}
		body := struct {
			Secret      string            `json:"secret,omitempty"`
			Name        string            `json:"name"`
			Level       string            `json:"level"`
			Duration    int64             `json:"duration"`
			Permissions []RobotPermission `json:"permissions"`
		}{"", strings.TrimPrefix(r.Name, "robot$"), "system", r.Duration, permissions(q, r.Push)}
		if material != nil {
			body.Secret = string(material.Bytes())
		}
		if _, e = c.lifecycleRequest(ctx, "POST", "/robots", body, &got, user, v, q.Check); e != nil {
			return out, e
		}
		if got.ID <= 0 || got.Secret == "" || len(got.Secret) > 4096 {
			return out, clientError("INTEGRITY_FAILURE")
		}
		secret := []byte(got.Secret)
		got.Secret = ""
		if material != nil {
			if !bytes.Equal(secret, material.Bytes()) {
				e = clientError("INTEGRITY_FAILURE")
			}
		} else {
			e = sink(ctx, r, bytes.NewReader(secret))
		}
		for i := range secret {
			secret[i] = 0
		}
		if e != nil {
			return out, e
		}
		q.Robots[i].ID = got.ID
		if got.Name != r.Name {
			return out, clientError("INTEGRITY_FAILURE")
		}
	}
	return c.ObserveLifecycle(ctx, q, user, v)
}
