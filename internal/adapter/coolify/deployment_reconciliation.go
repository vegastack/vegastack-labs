package coolify

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
)

// ObserveBoundDeployment makes only GET requests. It binds the explicitly
// selected receipt to the current application, primary destination and server.
func (c *Client) ObserveBoundDeployment(ctx context.Context, t ApplicationTarget, serverID int64, receipt string, v *credentialref.Value, check func() error) (out DeploymentReceipt, err error) {
	out = DeploymentReceipt{ApplicationUUID: t.ApplicationUUID, DeploymentUUID: receipt, Stage: "queued", ProviderStatus: "unknown"}
	if !c.valid(v) || check == nil || serverID <= 0 || !identifier.MatchString(receipt) {
		return out, ErrInput
	}
	// Guard every internal identity GET too, not only receipt requests.
	copyClient := *c
	httpClient := *c.http
	httpClient.Transport = deploymentReadTransport{next: c.http.Transport, check: check}
	copyClient.http = &httpClient
	c = &copyClient
	if err = check(); err != nil {
		return out, err
	}
	if _, err = c.ObserveApplication(ctx, t, v); err != nil {
		return out, err
	}
	if err = check(); err != nil {
		return out, err
	}
	var destinations []struct {
		UUID     string `json:"uuid"`
		ServerID int64  `json:"server_id"`
		Primary  *bool  `json:"is_primary"`
	}
	if err = c.deploymentRequest(ctx, http.MethodGet, "/applications/"+t.ApplicationUUID+"/destinations", nil, v, check, &destinations); err != nil {
		return out, err
	}
	if len(destinations) != 1 || destinations[0].ServerID != serverID || destinations[0].Primary == nil || !*destinations[0].Primary {
		return out, ErrIdentity
	}
	var list struct {
		Deployments []struct {
			UUID string `json:"deployment_uuid"`
		} `json:"deployments"`
	}
	if err = c.deploymentRequest(ctx, http.MethodGet, "/deployments/applications/"+t.ApplicationUUID+"?take=10", nil, v, check, &list); err != nil {
		return out, err
	}
	matches := 0
	for _, entry := range list.Deployments {
		if entry.UUID == receipt {
			matches++
		}
	}
	if len(list.Deployments) > 10 || matches != 1 {
		return out, ErrIdentity
	}
	var d struct {
		UUID          string      `json:"deployment_uuid"`
		Status        string      `json:"status"`
		ServerID      int64       `json:"server_id"`
		DestinationID json.Number `json:"destination_id"`
		CreatedAt     string      `json:"created_at"`
	}
	if err = c.deploymentRequest(ctx, http.MethodGet, "/deployments/"+receipt, nil, v, check, &d); err != nil {
		return out, err
	}
	destination, e := d.DestinationID.Int64()
	if d.UUID != receipt || d.ServerID != serverID || e != nil || destination != t.DestinationID || d.Status != "finished" {
		return out, ErrIdentity
	}
	stamp, e := time.Parse(time.RFC3339Nano, d.CreatedAt)
	if e != nil || stamp.IsZero() {
		return out, ErrIdentity
	}
	out.CreatedAt = stamp.UTC().Format(time.RFC3339Nano)
	out.ProviderStatus = d.Status
	if err = check(); err != nil {
		return out, err
	}
	return out, nil
}

// This adapter-local transport cannot dispatch a provider mutation.
type deploymentReadTransport struct {
	next  http.RoundTripper
	check func() error
}

func (t deploymentReadTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method != http.MethodGet {
		return nil, ErrInput
	}
	if e := t.check(); e != nil {
		return nil, e
	}
	next := t.next
	if next == nil {
		return nil, ErrInput
	}
	return next.RoundTrip(r)
}
