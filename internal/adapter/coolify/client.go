// Package coolify provides bounded read-only observations of Coolify v4.3.10.
// Its contract is https://github.com/coollabsio/coolify/blob/v4.3.10/openapi.json.
package coolify

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

const maxBody = 1 << 20

// Errors contain only fixed codes, never provider bodies, URLs or credentials.
var (
	ErrInput       = failure.New(generated.ErrorCodeInputInvalid, "coolify-observation", false)
	ErrIdentity    = failure.New(generated.ErrorCodeIntegrityFailure, "coolify-observation", false)
	ErrUnavailable = failure.New(generated.ErrorCodeDependencyUnavailable, "coolify-observation", false)
)

type Client struct {
	base string
	http *http.Client
}
type ApplicationTarget struct {
	TeamID, ProjectID, EnvironmentID, DestinationID            int64
	ProjectUUID, Environment, ApplicationUUID, DestinationType string
}
type ServerTarget struct {
	TeamID, ServerID int64
	ServerUUID       string
}

// ApplicationSnapshot contains configuration and provider-reported status only.
// The pinned API does not prove a running digest, health, or destination/server relation.
type ApplicationSnapshot struct {
	TeamID              int64  `json:"team_id"`
	ProjectID           int64  `json:"project_id"`
	ProjectUUID         string `json:"project_uuid"`
	EnvironmentID       int64  `json:"environment_id"`
	ApplicationUUID     string `json:"application_uuid"`
	DestinationID       int64  `json:"destination_id"`
	DestinationType     string `json:"destination_type"`
	ConfiguredImageName string `json:"configured_image_name,omitempty"`
	ConfiguredImageTag  string `json:"configured_image_tag,omitempty"`
	ProviderStatus      string `json:"provider_status"`
	ServerRelation      string `json:"server_relation"`
}
type ServerSnapshot struct {
	TeamID         int64  `json:"team_id"`
	ServerID       int64  `json:"server_id"`
	ServerUUID     string `json:"server_uuid"`
	ProviderStatus string `json:"provider_status"`
}

// NewClient accepts a protected configured HTTPS base, normally ending /api/v1.
// A supplied transport is a trusted composition boundary, not a user option.
func NewClient(baseURL string, transport http.RoundTripper) (*Client, error) {
	u, e := url.Parse(baseURL)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" || strings.ContainsAny(u.Path, "\\\r\n") {
		return nil, ErrInput
	}
	for _, part := range strings.Split(u.Path, "/") {
		if part == "." || part == ".." {
			return nil, ErrInput
		}
	}
	if transport == nil {
		transport = &http.Transport{Proxy: nil, ForceAttemptHTTP2: true, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second, IdleConnTimeout: 30 * time.Second, DisableKeepAlives: true}
	}
	return &Client{base: strings.TrimRight(u.String(), "/"), http: &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

var identifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)
var imageName = regexp.MustCompile(`^[a-z0-9][a-z0-9._:/-]{0,254}$`)
var imageTag = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)

func validCredential(v *credentialref.Value) bool {
	b := v.Bytes()
	return len(b) > 0 && len(b) <= 4096 && !strings.ContainsAny(string(b), "\r\n\x00") && strings.TrimSpace(string(b)) == string(b)
}
func (c *Client) valid(v *credentialref.Value) bool {
	return c != nil && c.http != nil && validCredential(v)
}
func validDestination(s string) bool {
	return s == `App\Models\StandaloneDocker` || s == `App\Models\SwarmDocker`
}

func (c *Client) ObserveApplication(ctx context.Context, q ApplicationTarget, v *credentialref.Value) (ApplicationSnapshot, error) {
	if !c.valid(v) || q.TeamID <= 0 || q.ProjectID <= 0 || q.EnvironmentID <= 0 || q.DestinationID <= 0 || !identifier.MatchString(q.ProjectUUID) || !identifier.MatchString(q.Environment) || !identifier.MatchString(q.ApplicationUUID) || !validDestination(q.DestinationType) {
		return ApplicationSnapshot{}, ErrInput
	}
	if e := c.team(ctx, q.TeamID, v); e != nil {
		return ApplicationSnapshot{}, e
	}
	var project struct {
		ID   int64  `json:"id"`
		UUID string `json:"uuid"`
	}
	if e := c.get(ctx, "/projects/"+q.ProjectUUID, v, &project); e != nil {
		return ApplicationSnapshot{}, e
	}
	if project.ID != q.ProjectID || project.UUID != q.ProjectUUID {
		return ApplicationSnapshot{}, ErrIdentity
	}
	var env struct {
		ID        int64  `json:"id"`
		ProjectID int64  `json:"project_id"`
		Name      string `json:"name"`
	}
	if e := c.get(ctx, "/projects/"+q.ProjectUUID+"/"+q.Environment, v, &env); e != nil {
		return ApplicationSnapshot{}, e
	}
	// Environment has no UUID in the pinned schema. The explicit numeric ID
	// and project relationship are authoritative even when a UUID selector is used.
	if env.ID != q.EnvironmentID || env.ProjectID != q.ProjectID {
		return ApplicationSnapshot{}, ErrIdentity
	}
	var app struct {
		UUID            string `json:"uuid"`
		EnvironmentID   int64  `json:"environment_id"`
		DestinationID   int64  `json:"destination_id"`
		DestinationType string `json:"destination_type"`
		Image           string `json:"docker_registry_image_name"`
		Tag             string `json:"docker_registry_image_tag"`
		Status          string `json:"status"`
	}
	if e := c.get(ctx, "/applications/"+q.ApplicationUUID, v, &app); e != nil {
		return ApplicationSnapshot{}, e
	}
	if app.UUID != q.ApplicationUUID || app.EnvironmentID != q.EnvironmentID || app.DestinationID != q.DestinationID || app.DestinationType != q.DestinationType {
		return ApplicationSnapshot{}, ErrIdentity
	}
	out := ApplicationSnapshot{TeamID: q.TeamID, ProjectID: q.ProjectID, ProjectUUID: q.ProjectUUID, EnvironmentID: q.EnvironmentID, ApplicationUUID: q.ApplicationUUID, DestinationID: q.DestinationID, DestinationType: q.DestinationType, ProviderStatus: status(app.Status), ServerRelation: "unknown"}
	// Only image-reference grammar is accepted; never return URLs, arbitrary text,
	// credentials, command lines, configuration, logs or provider error messages.
	if imageName.MatchString(app.Image) && !strings.Contains(app.Image, "://") && !strings.Contains(app.Image, string(v.Bytes())) {
		out.ConfiguredImageName = app.Image
	}
	if imageTag.MatchString(app.Tag) && !strings.Contains(app.Tag, string(v.Bytes())) {
		out.ConfiguredImageTag = app.Tag
	}
	return out, nil
}
func status(s string) string {
	switch s {
	case "running", "running:healthy", "running:unhealthy", "running:unknown", "exited", "stopped", "starting", "restarting", "degraded":
		return s
	default:
		return "unknown"
	}
}
func (c *Client) ObserveServer(ctx context.Context, q ServerTarget, v *credentialref.Value) (ServerSnapshot, error) {
	if !c.valid(v) || q.TeamID <= 0 || q.ServerID <= 0 || !identifier.MatchString(q.ServerUUID) {
		return ServerSnapshot{}, ErrInput
	}
	if e := c.team(ctx, q.TeamID, v); e != nil {
		return ServerSnapshot{}, e
	}
	var server struct {
		ID   int64  `json:"id"`
		UUID string `json:"uuid"`
	}
	if e := c.get(ctx, "/servers/"+q.ServerUUID, v, &server); e != nil {
		return ServerSnapshot{}, e
	}
	if server.ID != q.ServerID || server.UUID != q.ServerUUID {
		return ServerSnapshot{}, ErrIdentity
	}
	// No status/health field is established by the pinned Server schema.
	return ServerSnapshot{TeamID: q.TeamID, ServerID: q.ServerID, ServerUUID: q.ServerUUID, ProviderStatus: "unknown"}, nil
}
func (c *Client) team(ctx context.Context, id int64, v *credentialref.Value) error {
	var team struct {
		ID int64 `json:"id"`
	}
	if e := c.get(ctx, "/team", v, &team); e != nil {
		return e
	}
	if team.ID != id {
		return ErrIdentity
	}
	return nil
}
func (c *Client) get(ctx context.Context, path string, v *credentialref.Value, out any) error {
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)
	if e != nil {
		return ErrInput
	}
	req.Header.Set("Authorization", "Bearer "+string(v.Bytes()))
	req.Header.Set("Accept", "application/json")
	res, e := c.http.Do(req)
	if e != nil {
		return ErrUnavailable
	}
	defer res.Body.Close()
	switch res.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized:
		return failure.New(generated.ErrorCodeAuthenticationRequired, "coolify-observation", false)
	case http.StatusForbidden:
		return failure.New(generated.ErrorCodeAuthorizationDenied, "coolify-observation", false)
	case http.StatusNotFound:
		return failure.New(generated.ErrorCodeResourceNotFound, "coolify-observation", false)
	case http.StatusTooManyRequests:
		return failure.New(generated.ErrorCodeRateLimited, "coolify-observation", false)
	default:
		return ErrUnavailable
	}
	b, e := io.ReadAll(io.LimitReader(res.Body, maxBody+1))
	if e != nil || len(b) > maxBody {
		return ErrIdentity
	}
	if !uniqueJSON(b) || json.Unmarshal(b, out) != nil {
		return ErrIdentity
	}
	return nil
}

// uniqueJSON checks keys at every nesting level before typed decoding ignores
// unneeded sensitive fields. Only one complete object response is accepted.
func uniqueJSON(b []byte) bool {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	t, e := d.Token()
	if e != nil || t != json.Delim('{') {
		return false
	}
	if !jsonContainer(d, '{', 0) {
		return false
	}
	_, e = d.Token()
	return e == io.EOF
}
func jsonContainer(d *json.Decoder, open json.Delim, depth int) bool {
	if depth > 64 {
		return false
	}
	keys := map[string]bool{}
	for d.More() {
		if open == '{' {
			t, e := d.Token()
			k, ok := t.(string)
			if e != nil || !ok || keys[k] {
				return false
			}
			keys[k] = true
		}
		t, e := d.Token()
		if e != nil {
			return false
		}
		if delim, ok := t.(json.Delim); ok {
			if delim != '{' && delim != '[' || !jsonContainer(d, delim, depth+1) {
				return false
			}
		}
	}
	t, e := d.Token()
	return e == nil && ((open == '{' && t == json.Delim('}')) || (open == '[' && t == json.Delim(']')))
}
