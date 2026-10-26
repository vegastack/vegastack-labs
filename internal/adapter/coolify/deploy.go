package coolify

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
)

// ImageDeploymentRequest is restricted to one existing standalone image application.
// Check is required and runs before every provider request, including both writes.
type ImageDeploymentRequest struct {
	Target          ApplicationTarget
	DestinationUUID string
	ServerUUID      string
	ServerID        int64
	Repository      string
	Digest          string
	Environment     []EnvironmentValue
	Settings        *ImageSettings
	Check           func() error
}

// DeploymentReceipt records provider acknowledgement, never runtime digest proof.
// A nonempty attempted stage must be persisted even when the call returns an error.
type DeploymentReceipt struct {
	ApplicationUUID       string `json:"application_uuid"`
	DeploymentUUID        string `json:"deployment_uuid,omitempty"`
	Stage                 string `json:"stage"`
	ProviderStatus        string `json:"provider_status"`
	RuntimeDigestVerified bool   `json:"runtime_digest_verified"`
}

var digestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
var repositoryPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]*(?::[0-9]{1,5})?/[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$`)

// DeployImage follows the pinned v4.3.10 PATCH, deploy and receipt-read protocol.
// It never retries, rolls back, accepts fanout or changes build packs.
func (c *Client) DeployImage(ctx context.Context, q ImageDeploymentRequest, v *credentialref.Value) (DeploymentReceipt, error) {
	out := DeploymentReceipt{ApplicationUUID: q.Target.ApplicationUUID, Stage: "validated", ProviderStatus: "unknown"}
	t := q.Target
	if !c.valid(v) || q.Check == nil || t.TeamID <= 0 || t.ProjectID <= 0 || t.EnvironmentID <= 0 || t.DestinationID <= 0 || q.ServerID <= 0 || t.DestinationType != `App\Models\StandaloneDocker` || !identifier.MatchString(t.ProjectUUID) || !identifier.MatchString(t.Environment) || !identifier.MatchString(t.ApplicationUUID) || !identifier.MatchString(q.DestinationUUID) || !identifier.MatchString(q.ServerUUID) || len(q.Repository) > 255 || !repositoryPattern.MatchString(q.Repository) || !digestPattern.MatchString(q.Digest) || strings.Contains(q.Repository, string(v.Bytes())) {
		return out, ErrInput
	}
	read := func(path string, dst any) error {
		return c.deploymentRequest(ctx, http.MethodGet, path, nil, v, q.Check, dst)
	}
	var team struct {
		ID int64 `json:"id"`
	}
	if e := read("/team", &team); e != nil {
		return out, e
	}
	if team.ID != t.TeamID {
		return out, ErrIdentity
	}
	var project struct {
		ID   int64  `json:"id"`
		UUID string `json:"uuid"`
	}
	if e := read("/projects/"+t.ProjectUUID, &project); e != nil {
		return out, e
	}
	if project.ID != t.ProjectID || project.UUID != t.ProjectUUID {
		return out, ErrIdentity
	}
	var env struct {
		ID        int64 `json:"id"`
		ProjectID int64 `json:"project_id"`
	}
	if e := read("/projects/"+t.ProjectUUID+"/"+t.Environment, &env); e != nil {
		return out, e
	}
	if env.ID != t.EnvironmentID || env.ProjectID != t.ProjectID {
		return out, ErrIdentity
	}
	var app struct {
		UUID            string `json:"uuid"`
		EnvironmentID   int64  `json:"environment_id"`
		DestinationID   int64  `json:"destination_id"`
		DestinationType string `json:"destination_type"`
		BuildPack       string `json:"build_pack"`
		Servers         *int64 `json:"additional_servers_count"`
		Networks        *int64 `json:"additional_networks_count"`
	}
	if e := read("/applications/"+t.ApplicationUUID, &app); e != nil {
		return out, e
	}
	if app.UUID != t.ApplicationUUID || app.EnvironmentID != t.EnvironmentID || app.DestinationID != t.DestinationID || app.DestinationType != t.DestinationType || app.BuildPack != "dockerimage" || app.Servers == nil || app.Networks == nil || *app.Servers != 0 || *app.Networks != 0 {
		return out, ErrIdentity
	}
	var destinations []struct {
		UUID       string `json:"uuid"`
		ServerUUID string `json:"server_uuid"`
		ServerID   int64  `json:"server_id"`
		Primary    *bool  `json:"is_primary"`
	}
	if e := read("/applications/"+t.ApplicationUUID+"/destinations", &destinations); e != nil {
		return out, e
	}
	if len(destinations) != 1 {
		return out, ErrIdentity
	}
	d := destinations[0]
	if d.UUID != q.DestinationUUID || d.ServerUUID != q.ServerUUID || d.ServerID != q.ServerID || d.Primary == nil || !*d.Primary {
		return out, ErrIdentity
	}
	var server struct {
		ID   int64  `json:"id"`
		UUID string `json:"uuid"`
	}
	if e := read("/servers/"+q.ServerUUID, &server); e != nil {
		return out, e
	}
	if server.ID != q.ServerID || server.UUID != q.ServerUUID {
		return out, ErrIdentity
	}
	patch := map[string]any{"docker_registry_image_name": q.Repository, "docker_registry_image_tag": "sha256-" + strings.TrimPrefix(q.Digest, "sha256:")}
	if q.Settings != nil {
		raw, _ := json.Marshal(q.Settings)
		var fields map[string]any
		if json.Unmarshal(raw, &fields) != nil {
			return out, ErrInput
		}
		for k, v := range fields {
			patch[k] = v
		}
	}
	// Run the mutation check before recording attempted effects; the request helper
	// checks again immediately before dispatch to close cancellation windows.
	if e := q.Check(); e != nil {
		return out, e
	}
	if len(q.Environment) > 0 {
		out.Stage = "environment_attempted"
		if e := c.applyEnvironment(ctx, t.ApplicationUUID, q.Environment, v, q.Check); e != nil {
			return out, e
		}
	}
	out.Stage = "patch_attempted"
	var updated struct {
		UUID string `json:"uuid"`
	}
	if e := c.deploymentRequest(ctx, http.MethodPatch, "/applications/"+t.ApplicationUUID, patch, v, q.Check, &updated); e != nil {
		return out, e
	}
	if updated.UUID != t.ApplicationUUID {
		return out, ErrIdentity
	}
	if q.Settings != nil {
		if e := c.VerifyImageSettings(ctx, t.ApplicationUUID, *q.Settings, v, q.Check); e != nil {
			return out, e
		}
	}
	out.Stage = "configured"
	if e := q.Check(); e != nil {
		return out, e
	}
	out.Stage = "deploy_attempted"
	var queued struct {
		Deployments []struct {
			Resource string `json:"resource_uuid"`
			UUID     string `json:"deployment_uuid"`
		} `json:"deployments"`
	}
	if e := c.deploymentRequest(ctx, http.MethodPost, "/deploy", struct {
		UUID string `json:"uuid"`
	}{t.ApplicationUUID}, v, q.Check, &queued); e != nil {
		return out, e
	}
	if len(queued.Deployments) != 1 || queued.Deployments[0].Resource != t.ApplicationUUID || !identifier.MatchString(queued.Deployments[0].UUID) || strings.Contains(queued.Deployments[0].UUID, string(v.Bytes())) {
		return out, ErrIdentity
	}
	out.DeploymentUUID = queued.Deployments[0].UUID
	status, e := c.observeDeployment(ctx, t.ApplicationUUID, out.DeploymentUUID, v, q.Check, q.ServerID, t.DestinationID)
	if e != nil {
		return out, e
	}
	out.Stage = "queued"
	out.ProviderStatus = status
	return out, nil
}

// ObserveDeployment uses bounded application membership plus the exact receipt.
// Absence from the most recent ten deployments fails closed; no replay is safe.
func (c *Client) ObserveDeployment(ctx context.Context, applicationUUID, deploymentUUID string, v *credentialref.Value) (DeploymentReceipt, error) {
	out := DeploymentReceipt{ApplicationUUID: applicationUUID, DeploymentUUID: deploymentUUID, Stage: "queued", ProviderStatus: "unknown"}
	if !c.valid(v) || !identifier.MatchString(applicationUUID) || !identifier.MatchString(deploymentUUID) {
		return out, ErrInput
	}
	s, e := c.observeDeployment(ctx, applicationUUID, deploymentUUID, v, nil, 0, 0)
	if e == nil {
		out.ProviderStatus = s
	}
	return out, e
}
func (c *Client) observeDeployment(ctx context.Context, app, receipt string, v *credentialref.Value, check func() error, serverID, destinationID int64) (string, error) {
	var list struct {
		Deployments []struct {
			UUID string `json:"deployment_uuid"`
		} `json:"deployments"`
	}
	if e := c.deploymentRequest(ctx, http.MethodGet, "/deployments/applications/"+app+"?take=10", nil, v, check, &list); e != nil {
		return "unknown", e
	}
	matches := 0
	for _, d := range list.Deployments {
		if d.UUID == receipt {
			matches++
		}
	}
	if len(list.Deployments) > 10 || matches != 1 {
		return "unknown", ErrIdentity
	}
	var d struct {
		UUID          string      `json:"deployment_uuid"`
		Status        string      `json:"status"`
		ServerID      int64       `json:"server_id"`
		DestinationID json.Number `json:"destination_id"`
	}
	if e := c.deploymentRequest(ctx, http.MethodGet, "/deployments/"+receipt, nil, v, check, &d); e != nil {
		return "unknown", e
	}
	dest, e := d.DestinationID.Int64()
	if d.UUID != receipt || (serverID > 0 && d.ServerID != serverID) || (destinationID > 0 && (e != nil || dest != destinationID)) {
		return "unknown", ErrIdentity
	}
	switch d.Status {
	case "queued", "in_progress", "finished", "failed", "cancelled-by-user":
		return d.Status, nil
	}
	return "unknown", ErrIdentity
}
func (c *Client) deploymentRequest(ctx context.Context, method, path string, body any, v *credentialref.Value, check func() error, out any) error {
	if check != nil {
		if e := check(); e != nil {
			return e
		}
	}
	var payload []byte
	var e error
	if body != nil {
		payload, e = json.Marshal(body)
		if e != nil {
			return ErrInput
		}
	}
	req, e := http.NewRequestWithContext(ctx, method, c.base+path, bytes.NewReader(payload))
	if e != nil {
		return ErrInput
	}
	req.Header.Set("Authorization", "Bearer "+string(v.Bytes()))
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, e := c.http.Do(req)
	if e != nil {
		return ErrUnavailable
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return ErrUnavailable
	}
	b, e := io.ReadAll(io.LimitReader(res.Body, maxBody+1))
	if e != nil || len(b) > maxBody {
		return ErrIdentity
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	tok, e := dec.Token()
	open, ok := tok.(json.Delim)
	if e != nil || !ok || (open != '{' && open != '[') || !jsonContainer(dec, open, 0) {
		return ErrIdentity
	}
	if _, e = dec.Token(); e != io.EOF {
		return ErrIdentity
	}
	if json.Unmarshal(b, out) != nil {
		return ErrIdentity
	}
	return nil
}
