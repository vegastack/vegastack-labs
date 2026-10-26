// Package cloudflare binds the selected official SDK to bounded typed workflows.
package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	cf "github.com/cloudflare/cloudflare-go/v7"
	"github.com/cloudflare/cloudflare-go/v7/option"
	zt "github.com/cloudflare/cloudflare-go/v7/zero_trust"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	mesh "github.com/vegastack/vegastack-labs/internal/networkmesh"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"
)

type Backend interface {
	Observe(context.Context, generated.MeshChange, *credentialref.Value) (mesh.Snapshot, error)
	Mutate(context.Context, generated.MeshChange, *credentialref.Value) error
}
type SDKClient struct {
	transport http.RoundTripper
	base      string
}

func NewClientWithTransport(t http.RoundTripper) *SDKClient {
	if t == nil {
		t = http.DefaultTransport
	}
	return &SDKClient{transport: t, base: "https://api.cloudflare.com/client/v4/"}
}
func NewClient() *SDKClient {
	return &SDKClient{transport: http.DefaultTransport, base: "https://api.cloudflare.com/client/v4/"}
}

type boundedTransport struct{ next http.RoundTripper }

func (t boundedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	res, e := t.next.RoundTrip(r)
	if e != nil {
		return nil, mesh.Error(generated.ErrorCodeDependencyUnavailable)
	}
	b, e := io.ReadAll(io.LimitReader(res.Body, (1<<20)+1))
	res.Body.Close()
	if e != nil || len(b) > 1<<20 {
		return nil, mesh.Error(generated.ErrorCodeIntegrityFailure)
	}
	if res.StatusCode >= 300 && res.StatusCode < 400 {
		return nil, mesh.Error(generated.ErrorCodeDependencyUnavailable)
	}
	var env struct {
		Success    *bool `json:"success"`
		ResultInfo *struct {
			TotalCount *int   `json:"total_count"`
			Count      int    `json:"count"`
			Cursor     string `json:"cursor"`
		} `json:"result_info"`
		Result json.RawMessage `json:"result"`
	}
	if res.StatusCode >= 200 && res.StatusCode < 300 {
		if json.Unmarshal(b, &env) != nil || env.Success == nil || !*env.Success {
			return nil, mesh.Error(generated.ErrorCodeIntegrityFailure)
		}
		if env.ResultInfo != nil && env.ResultInfo.TotalCount != nil && env.ResultInfo.Cursor == "" {
			var rows []json.RawMessage
			if json.Unmarshal(env.Result, &rows) == nil && *env.ResultInfo.TotalCount > len(rows) {
				return nil, mesh.Error(generated.ErrorCodeIntegrityFailure)
			}
		}
	}
	res.Body = io.NopCloser(bytes.NewReader(b))
	return res, nil
}
func (c *SDKClient) options(v *credentialref.Value) ([]option.RequestOption, error) {
	if c == nil || v == nil || len(v.Bytes()) == 0 || strings.ContainsAny(string(v.Bytes()), "\r\n") {
		return nil, mesh.Error(generated.ErrorCodePrerequisiteBlocked)
	}
	return []option.RequestOption{option.WithBaseURL(c.base), option.WithAPIToken(string(v.Bytes())), option.WithMaxRetries(0), option.WithHTTPClient(&http.Client{Transport: boundedTransport{c.transport}, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }})}, nil
}
func (c *SDKClient) Observe(ctx context.Context, q generated.MeshChange, v *credentialref.Value) (out mesh.Snapshot, err error) {
	opts, e := c.options(v)
	if e != nil {
		return out, e
	}
	defer func() {
		if err != nil {
			err = mesh.Error(generated.ErrorCodeDependencyUnavailable)
		}
	}()
	out.Present = true
	out.Reason = "configuration-observed"
	switch q.ResourceKind {
	case "registration":
		svc := zt.NewDeviceRegistrationService(opts...)
		cursor := ""
		seen := map[string]bool{}
		found := false
		for page := 0; page < 32; page++ {
			p, e := svc.List(ctx, zt.DeviceRegistrationListParams{AccountID: cf.F(q.AccountID), ID: cf.F([]string{q.ResourceID}), Cursor: cf.F(cursor), PerPage: cf.F(int64(100)), Status: cf.F(zt.DeviceRegistrationListParamsStatus("all"))})
			if e != nil {
				return out, e
			}
			for _, r := range p.Result {
				if r.ID != q.ResourceID || found {
					return out, mesh.Error(generated.ErrorCodeIntegrityFailure)
				}
				found = true
				out.RegistrationID = r.ID
				out.PhysicalDeviceID = r.Device.ID
				out.ProviderUserID = r.User.ID
				out.VirtualIPv4 = r.VirtualIPV4
				if r.DeletedAt != "" || r.RevokedAt != "" {
					out.Present = false
					out.Reason = "registration-inactive"
				}
			}
			cursor = p.ResultInfo.Cursor
			if cursor == "" {
				out.Present = found && out.Present
				out.Digest = mesh.Digest(out)
				return out, nil
			}
			if seen[cursor] {
				return out, mesh.Error(generated.ErrorCodeIntegrityFailure)
			}
			seen[cursor] = true
		}
		return out, mesh.Error(generated.ErrorCodeIntegrityFailure)
	case "profile-include":
		p, e := zt.NewDevicePolicyCustomIncludeService(opts...).Get(ctx, q.ResourceID, zt.DevicePolicyCustomIncludeGetParams{AccountID: cf.F(q.AccountID)})
		if e != nil {
			return out, e
		}
		out.Routes = []generated.MeshRoute{}
		for _, r := range p.Result {
			if r.Host != "" || r.Description != "" || !mesh.ValidRoute(r.Address) {
				return out, mesh.Error(generated.ErrorCodePrerequisiteBlocked)
			}
			out.Routes = append(out.Routes, generated.MeshRoute{Schema: generated.SchemaIDMeshRoute, SchemaVersion: "1.0.0", Address: r.Address})
		}
	case "profile-exclude":
		p, e := zt.NewDevicePolicyCustomExcludeService(opts...).Get(ctx, q.ResourceID, zt.DevicePolicyCustomExcludeGetParams{AccountID: cf.F(q.AccountID)})
		if e != nil {
			return out, e
		}
		out.Routes = []generated.MeshRoute{}
		for _, r := range p.Result {
			if r.Host != "" || r.Description != "" || !mesh.ValidRoute(r.Address) {
				return out, mesh.Error(generated.ErrorCodePrerequisiteBlocked)
			}
			out.Routes = append(out.Routes, generated.MeshRoute{Schema: generated.SchemaIDMeshRoute, SchemaVersion: "1.0.0", Address: r.Address})
		}
	case "gateway-rule":
		r, e := zt.NewGatewayRuleService(opts...).Get(ctx, q.ResourceID, zt.GatewayRuleGetParams{AccountID: cf.F(q.AccountID)})
		if e != nil {
			return out, e
		}
		if r.ID != q.ResourceID || r.ReadOnly || len(r.Filters) != 1 || string(r.Filters[0]) != "l4" || r.Description != "" || r.DevicePosture != "" {
			return out, mesh.Error(generated.ErrorCodePrerequisiteBlocked)
		}
		var fields map[string]json.RawMessage
		json.Unmarshal([]byte(r.JSON.RawJSON()), &fields)
		for _, k := range []string{"rule_settings", "schedule", "expiration"} {
			if raw := fields[k]; len(raw) > 0 && string(raw) != "null" && string(raw) != "{}" {
				return out, mesh.Error(generated.ErrorCodePrerequisiteBlocked)
			}
		}
		out.RuleName = r.Name
		out.RuleAction = string(r.Action)
		out.Traffic = r.Traffic
		out.Identity = r.Identity
		out.Precedence = r.Precedence
		out.Enabled = r.Enabled
	default:
		return out, mesh.Error(generated.ErrorCodeInputInvalid)
	}
	slices.SortFunc(out.Routes, func(a, b generated.MeshRoute) int { return strings.Compare(a.Address, b.Address) })
	out.Digest = mesh.Digest(out)
	return out, nil
}
func (c *SDKClient) Mutate(ctx context.Context, q generated.MeshChange, v *credentialref.Value) (err error) {
	opts, e := c.options(v)
	if e != nil {
		return e
	}
	defer func() {
		if err != nil {
			err = mesh.Error(generated.ErrorCodeRecoveryRequired)
		}
	}()
	switch q.Action {
	case "registration-delete":
		_, err = zt.NewDeviceRegistrationService(opts...).Delete(ctx, q.ResourceID, zt.DeviceRegistrationDeleteParams{AccountID: cf.F(q.AccountID)})
	case "profile-routing-update":
		if q.ResourceKind == "profile-include" {
			body := []zt.SplitTunnelIncludeUnionParam{}
			for _, r := range q.Routes {
				body = append(body, zt.SplitTunnelIncludeTeamsDevicesIncludeSplitTunnelWithAddressParam{Address: cf.F(r.Address)})
			}
			_, err = zt.NewDevicePolicyCustomIncludeService(opts...).Update(ctx, q.ResourceID, zt.DevicePolicyCustomIncludeUpdateParams{AccountID: cf.F(q.AccountID), Body: body})
		} else {
			body := []zt.SplitTunnelExcludeUnionParam{}
			for _, r := range q.Routes {
				body = append(body, zt.SplitTunnelExcludeTeamsDevicesExcludeSplitTunnelWithAddressParam{Address: cf.F(r.Address)})
			}
			_, err = zt.NewDevicePolicyCustomExcludeService(opts...).Update(ctx, q.ResourceID, zt.DevicePolicyCustomExcludeUpdateParams{AccountID: cf.F(q.AccountID), Body: body})
		}
	case "gateway-rule-update":
		_, err = zt.NewGatewayRuleService(opts...).Update(ctx, q.ResourceID, zt.GatewayRuleUpdateParams{AccountID: cf.F(q.AccountID), Name: cf.F(q.RuleName), Action: cf.F(zt.GatewayRuleUpdateParamsAction(q.RuleAction)), Filters: cf.F([]zt.GatewayFilter{"l4"}), Traffic: cf.F(q.Traffic), Identity: cf.F(q.RuleIdentity), Precedence: cf.F(q.Precedence), Enabled: cf.F(q.Enabled)})
	default:
		return mesh.Error(generated.ErrorCodeInputInvalid)
	}
	return err
}
