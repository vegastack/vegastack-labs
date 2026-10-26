package coolify

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"io"
	"net/http"
	"strings"
)

// ResourceRequest is server-owned configuration. Empty external UUIDs request
// creation; exact name matches are never silently imported/adopted.
type ResourceRequest struct {
	TeamID          int64  `json:"teamId"`
	ProjectUUID     string `json:"projectUuid,omitempty"`
	ProjectName     string `json:"projectName"`
	Environment     string `json:"environment"`
	ServerID        int64  `json:"serverId,omitempty"`
	ServerAddress   string `json:"serverAddress,omitempty"`
	ServerUUID      string `json:"serverUuid,omitempty"`
	DestinationUUID string `json:"destinationUuid,omitempty"`
	ApplicationUUID string `json:"applicationUuid,omitempty"`
	ApplicationName string `json:"applicationName,omitempty"`
	Image           string `json:"image,omitempty"`
	ImageTag        string `json:"imageTag,omitempty"`
	Ports           string `json:"ports,omitempty"`
	// Compose is protected application-owned content, never user API input.
	Compose     string       `json:"compose,omitempty"`
	ServiceUUID string       `json:"serviceUuid,omitempty"`
	Check       func() error `json:"-"`
}
type ResourceSnapshot struct {
	TeamID          int64  `json:"teamId"`
	ProjectID       int64  `json:"projectId"`
	ProjectUUID     string `json:"projectUuid"`
	EnvironmentID   int64  `json:"environmentId"`
	Environment     string `json:"environment"`
	ApplicationUUID string `json:"applicationUuid,omitempty"`
	ServiceUUID     string `json:"serviceUuid,omitempty"`
}

func (c *Client) resourceRequest(ctx context.Context, method, path string, in, out any, v *credentialref.Value, check func() error) error {
	if !c.valid(v) || check == nil {
		return ErrInput
	}
	if e := check(); e != nil {
		return e
	}
	var body []byte
	var e error
	if in != nil {
		body, e = json.Marshal(in)
		if e != nil {
			return ErrInput
		}
	}
	req, e := http.NewRequestWithContext(ctx, method, c.base+path, bytes.NewReader(body))
	if e != nil {
		return ErrInput
	}
	req.Header.Set("Authorization", "Bearer "+string(v.Bytes()))
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, e := c.http.Do(req)
	if e != nil {
		return ErrUnavailable
	}
	defer res.Body.Close()
	allowed := res.StatusCode == 200 || (method == "POST" && res.StatusCode == 201) || (method == "PATCH" && res.StatusCode == 204)
	if !allowed {
		return ErrUnavailable
	}
	b, e := io.ReadAll(io.LimitReader(res.Body, maxBody+1))
	if e != nil || len(b) > maxBody {
		return ErrIdentity
	}
	if out == nil && len(bytes.TrimSpace(b)) == 0 {
		return check()
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	tok, e := dec.Token()
	d, ok := tok.(json.Delim)
	if e != nil || !ok || (d != '{' && d != '[') || !jsonContainer(dec, d, 0) {
		return ErrIdentity
	}
	if _, e = dec.Token(); e != io.EOF {
		return ErrIdentity
	}
	if out != nil && json.Unmarshal(b, out) != nil {
		return ErrIdentity
	}
	return check()
}
func (c *Client) validateResource(q ResourceRequest, v *credentialref.Value) error {
	if !c.valid(v) || q.Check == nil || q.TeamID <= 0 || !identifier.MatchString(q.ProjectName) || !identifier.MatchString(q.Environment) || len(q.Compose) > 262144 {
		return ErrInput
	}
	for _, id := range []string{q.ProjectUUID, q.ServerUUID, q.DestinationUUID, q.ApplicationUUID, q.ServiceUUID, q.ApplicationName} {
		if id != "" && !identifier.MatchString(id) {
			return ErrInput
		}
	}
	if q.Image != "" && (!imageName.MatchString(q.Image) || !imageTag.MatchString(q.ImageTag) || q.ServerUUID == "" || q.DestinationUUID == "" || q.ApplicationName == "" || q.Ports == "") {
		return ErrInput
	}
	if q.Compose != "" && (q.Image != "" || q.ApplicationName == "" || q.ServerUUID == "" || q.DestinationUUID == "") {
		return ErrInput
	}
	if strings.ContainsAny(q.Ports, "\r\n\\\x00") {
		return ErrInput
	}
	return nil
}
func (c *Client) ObserveResources(ctx context.Context, q ResourceRequest, v *credentialref.Value) (ResourceSnapshot, error) {
	var out ResourceSnapshot
	if e := c.validateResource(q, v); e != nil {
		return out, e
	}
	read := func(p string, o any) error { return c.resourceRequest(ctx, "GET", p, nil, o, v, q.Check) }
	var team struct {
		ID int64 `json:"id"`
	}
	if e := read("/team", &team); e != nil {
		return out, e
	}
	if team.ID != q.TeamID {
		return out, ErrIdentity
	}
	out.TeamID = team.ID
	if q.ServerUUID != "" {
		var server struct {
			ID   int64  `json:"id"`
			UUID string `json:"uuid"`
			IP   string `json:"ip"`
		}
		if e := read("/servers/"+q.ServerUUID, &server); e != nil {
			return out, e
		}
		if q.ServerID <= 0 || q.ServerAddress == "" || server.UUID != q.ServerUUID || server.ID != q.ServerID || server.IP != q.ServerAddress {
			return out, ErrIdentity
		}
		var destinations []struct {
			UUID     string `json:"uuid"`
			ServerID int64  `json:"server_id"`
		}
		if e := read("/servers/"+q.ServerUUID+"/destinations", &destinations); e != nil {
			return out, e
		}
		found := 0
		for _, d := range destinations {
			if d.UUID == q.DestinationUUID && d.ServerID == q.ServerID {
				found++
			}
		}
		if len(destinations) > 128 || found != 1 {
			return out, ErrIdentity
		}
	}
	if q.ProjectUUID == "" {
		var list []struct {
			Name string `json:"name"`
		}
		if e := read("/projects", &list); e != nil {
			return out, e
		}
		if len(list) > 1000 {
			return out, ErrIdentity
		}
		for _, p := range list {
			if p.Name == q.ProjectName {
				return out, ErrIdentity
			}
		}
		return out, nil
	}
	var p struct {
		ID     int64  `json:"id"`
		UUID   string `json:"uuid"`
		Name   string `json:"name"`
		TeamID int64  `json:"team_id"`
	}
	if e := read("/projects/"+q.ProjectUUID, &p); e != nil {
		return out, e
	}
	if p.UUID != q.ProjectUUID || p.ID <= 0 || p.TeamID != q.TeamID || p.Name != q.ProjectName {
		return out, ErrIdentity
	}
	out.ProjectID = p.ID
	out.ProjectUUID = p.UUID
	var envs []struct {
		ID        int64  `json:"id"`
		Name      string `json:"name"`
		ProjectID int64  `json:"project_id"`
	}
	if e := read("/projects/"+p.UUID+"/environments", &envs); e != nil {
		return out, e
	}
	if len(envs) > 1000 {
		return out, ErrIdentity
	}
	for _, env := range envs {
		if env.Name == q.Environment {
			if out.EnvironmentID != 0 || env.ProjectID != p.ID || env.ID <= 0 {
				return out, ErrIdentity
			}
			out.EnvironmentID = env.ID
			out.Environment = env.Name
		}
	}
	if q.ApplicationUUID != "" {
		var a struct {
			UUID          string `json:"uuid"`
			EnvironmentID int64  `json:"environment_id"`
		}
		if e := read("/applications/"+q.ApplicationUUID, &a); e != nil {
			return out, e
		}
		if a.UUID != q.ApplicationUUID || a.EnvironmentID != out.EnvironmentID {
			return out, ErrIdentity
		}
		out.ApplicationUUID = a.UUID
	}
	if q.ServiceUUID != "" {
		var a struct {
			UUID          string `json:"uuid"`
			EnvironmentID int64  `json:"environment_id"`
		}
		if e := read("/services/"+q.ServiceUUID, &a); e != nil {
			return out, e
		}
		if a.UUID != q.ServiceUUID || a.EnvironmentID != out.EnvironmentID {
			return out, ErrIdentity
		}
		out.ServiceUUID = a.UUID
	}
	return out, nil
}

// ApplyResources never retries a create or adopts a name collision. Newly created
// IDs are returned only after independent exact GET verification.
func (c *Client) ApplyResources(ctx context.Context, q ResourceRequest, v *credentialref.Value) (ResourceSnapshot, error) {
	out, e := c.ObserveResources(ctx, q, v)
	if e != nil {
		return out, e
	}
	if out.ProjectUUID == "" {
		var p struct {
			UUID string `json:"uuid"`
		}
		if e = c.resourceRequest(ctx, "POST", "/projects", struct {
			Name string `json:"name"`
		}{q.ProjectName}, &p, v, q.Check); e != nil {
			return out, e
		}
		if !identifier.MatchString(p.UUID) || strings.Contains(p.UUID, string(v.Bytes())) {
			return out, ErrIdentity
		}
		q.ProjectUUID = p.UUID
		out, e = c.ObserveResources(ctx, q, v)
		if e != nil {
			return out, e
		}
	}
	if out.EnvironmentID == 0 {
		var created struct {
			UUID string `json:"uuid"`
		}
		if e = c.resourceRequest(ctx, "POST", "/projects/"+q.ProjectUUID+"/environments", struct {
			Name string `json:"name"`
		}{q.Environment}, &created, v, q.Check); e != nil {
			return out, e
		}
		out, e = c.ObserveResources(ctx, q, v)
		if e != nil || out.EnvironmentID <= 0 {
			return out, ErrIdentity
		}
	}
	if q.Image != "" && out.ApplicationUUID == "" {
		var a struct {
			UUID string `json:"uuid"`
		}
		body := map[string]any{"project_uuid": q.ProjectUUID, "server_uuid": q.ServerUUID, "environment_name": q.Environment, "destination_uuid": q.DestinationUUID, "docker_registry_image_name": q.Image, "docker_registry_image_tag": q.ImageTag, "ports_exposes": q.Ports, "name": q.ApplicationName, "instant_deploy": false}
		if e = c.resourceRequest(ctx, "POST", "/applications/dockerimage", body, &a, v, q.Check); e != nil {
			return out, e
		}
		if !identifier.MatchString(a.UUID) || strings.Contains(a.UUID, string(v.Bytes())) {
			return out, ErrIdentity
		}
		q.ApplicationUUID = a.UUID
	}
	if q.Compose != "" && out.ServiceUUID == "" {
		var a struct {
			UUID string `json:"uuid"`
		}
		body := map[string]any{"project_uuid": q.ProjectUUID, "server_uuid": q.ServerUUID, "environment_name": q.Environment, "destination_uuid": q.DestinationUUID, "docker_compose_raw": q.Compose, "name": q.ApplicationName, "instant_deploy": false}
		if e = c.resourceRequest(ctx, "POST", "/services", body, &a, v, q.Check); e != nil {
			return out, e
		}
		if !identifier.MatchString(a.UUID) || strings.Contains(a.UUID, string(v.Bytes())) {
			return out, ErrIdentity
		}
		q.ServiceUUID = a.UUID
	}
	return c.ObserveResources(ctx, q, v)
}
