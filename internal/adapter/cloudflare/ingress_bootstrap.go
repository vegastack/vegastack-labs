package cloudflare

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"

	cf "github.com/cloudflare/cloudflare-go/v7"
	"github.com/cloudflare/cloudflare-go/v7/dns"
	"github.com/cloudflare/cloudflare-go/v7/option"
	zt "github.com/cloudflare/cloudflare-go/v7/zero_trust"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	ingress "github.com/vegastack/vegastack-labs/internal/networkingress"
)

var bootstrapResourceUUID = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)

// Bootstrap effects are finite and never return provider response bodies. The
// server reserves each stage before calling this client; an uncertain creation
// is reconciled separately rather than retried automatically.
func bootstrapInput(q generated.IngressChange) error {
	if q.ResourceID != "" && (q.Action == "bootstrap-cutover" && q.ResourceID != q.DNSRecordID || q.Action != "bootstrap-cutover" && !bootstrapResourceUUID.MatchString(q.ResourceID)) {
		return ingress.Error(generated.ErrorCodeInputInvalid)
	}
	q.ResourceID = "" // Only server-owned receipts supply an observation ID.
	return ingress.ValidateBootstrap(q)
}

func bootstrapSnapshot(q generated.IngressChange, s ingress.Snapshot) ingress.Snapshot {
	s.Digest = ingress.Digest([]any{q.AccountID, q.ZoneID, q.Hostname, q.Action, s.Present, s.ResourceID, s.StateDigest})
	return s
}

func bootstrapPublicState(raw map[string]json.RawMessage, keys ...string) string {
	public := map[string]json.RawMessage{}
	for _, k := range keys {
		if v, ok := raw[k]; ok {
			public[k] = v
		}
	}
	return ingress.Digest(public)
}

func bootstrapObject(rawJSON, id, name string) (map[string]json.RawMessage, error) {
	raw, err := rawObject(rawJSON)
	if err != nil || rawText(raw, "id") != id || rawText(raw, "name") != name {
		return nil, ingress.Error(generated.ErrorCodeIntegrityFailure)
	}
	return raw, nil
}

func bootstrapGroup(raw map[string]json.RawMessage, email string) bool {
	var include []struct {
		Email *struct {
			Email string `json:"email"`
		} `json:"email"`
	}
	if json.Unmarshal(raw["include"], &include) != nil || len(include) != 1 || include[0].Email == nil || include[0].Email.Email != email {
		return false
	}
	for _, key := range []string{"exclude", "require"} {
		var rules []json.RawMessage
		if v := raw[key]; len(v) > 0 && json.Unmarshal(v, &rules) != nil || len(rules) != 0 {
			return false
		}
	}
	var isDefault bool
	if v := raw["is_default"]; len(v) > 0 && json.Unmarshal(v, &isDefault) != nil || isDefault {
		return false
	}
	// Reject rules with additional selectors, even when an email also matches.
	var selectors []map[string]json.RawMessage
	return json.Unmarshal(raw["include"], &selectors) == nil && len(selectors[0]) == 1
}

func bootstrapPolicy(raw map[string]json.RawMessage, group string) bool {
	ids := policyGroupIDs(raw)
	if rawText(raw, "decision") != "allow" || len(ids) != 1 || ids[0] != group {
		return false
	}
	var include []map[string]json.RawMessage
	if json.Unmarshal(raw["include"], &include) != nil || len(include) != 1 || len(include[0]) != 1 {
		return false
	}
	for _, key := range []string{"exclude", "require"} {
		var rules []json.RawMessage
		if v := raw[key]; len(v) > 0 && json.Unmarshal(v, &rules) != nil || len(rules) != 0 {
			return false
		}
	}
	var precedence int64
	var reusable bool
	var appCount int
	_ = json.Unmarshal(raw["precedence"], &precedence)
	_ = json.Unmarshal(raw["reusable"], &reusable)
	_ = json.Unmarshal(raw["app_count"], &appCount)
	return precedence == 0 && !reusable && appCount <= 1
}

func bootstrapRules(q generated.IngressChange) []map[string]any {
	origin := map[string]any{"originServerName": q.OriginServerName, "noTLSVerify": false}
	if q.Bootstrap.OriginCAPool != "" {
		origin["caPool"] = q.Bootstrap.OriginCAPool
	}
	return []map[string]any{{"hostname": q.Hostname, "service": q.OriginService, "originRequest": origin}, {"service": "http_status:404"}}
}

func bootstrapConfigOwned(config map[string]json.RawMessage) bool {
	for key, raw := range config {
		switch key {
		case "ingress":
		case "originRequest":
			var defaults map[string]json.RawMessage
			if json.Unmarshal(raw, &defaults) != nil || len(defaults) != 0 {
				return false
			}
		case "warp-routing":
			var routing map[string]json.RawMessage
			if json.Unmarshal(raw, &routing) != nil || len(routing) != 1 || string(routing["enabled"]) != "false" {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func (c *SDKClient) ObserveBootstrap(ctx context.Context, q generated.IngressChange, v *credentialref.Value) (out ingress.Snapshot, err error) {
	if err = bootstrapInput(q); err != nil {
		return out, err
	}
	opts, err := c.options(v)
	if err != nil {
		return out, err
	}
	defer func() {
		if err != nil {
			err = ingress.Error(generated.ErrorCodeDependencyUnavailable)
		}
	}()
	out.Reason = "bootstrap-observed"
	out.StateDigest = ingress.Digest([]string{q.ResourceKind, q.Bootstrap.Name, "absent"})
	var raw map[string]json.RawMessage
	switch q.Action {
	case "bootstrap-tunnel":
		if q.ResourceID == "" {
			page, e := zt.NewTunnelCloudflaredService(opts...).List(ctx, zt.TunnelCloudflaredListParams{AccountID: cf.F(q.AccountID), Name: cf.F(q.Bootstrap.Name), IsDeleted: cf.F(false), PerPage: cf.F(float64(100))})
			if e != nil {
				return out, e
			}
			if len(page.Result) != 0 {
				return out, ingress.Error(generated.ErrorCodeStateConflict)
			}
			return bootstrapSnapshot(q, out), nil
		}
		r, e := zt.NewTunnelCloudflaredService(opts...).Get(ctx, q.ResourceID, zt.TunnelCloudflaredGetParams{AccountID: cf.F(q.AccountID)})
		if e != nil {
			return out, e
		}
		raw, err = bootstrapObject(r.JSON.RawJSON(), q.ResourceID, q.Bootstrap.Name)
		if err != nil || rawText(raw, "config_src") != "cloudflare" || rawText(raw, "deleted_at") != "" {
			return out, ingress.Error(generated.ErrorCodeIntegrityFailure)
		}
		out.StateDigest = bootstrapPublicState(raw, "id", "name", "config_src")
	case "bootstrap-group":
		if q.ResourceID == "" {
			page, e := zt.NewAccessGroupService(opts...).List(ctx, zt.AccessGroupListParams{AccountID: cf.F(q.AccountID), Name: cf.F(q.Bootstrap.Name), PerPage: cf.F(int64(100))})
			if e != nil {
				return out, e
			}
			if len(page.Result) != 0 {
				return out, ingress.Error(generated.ErrorCodeStateConflict)
			}
			return bootstrapSnapshot(q, out), nil
		}
		r, e := zt.NewAccessGroupService(opts...).Get(ctx, q.ResourceID, zt.AccessGroupGetParams{AccountID: cf.F(q.AccountID)})
		if e != nil {
			return out, e
		}
		raw, err = bootstrapObject(r.JSON.RawJSON(), q.ResourceID, q.Bootstrap.Name)
		if err != nil || !bootstrapGroup(raw, q.Bootstrap.AllowedEmail) {
			return out, ingress.Error(generated.ErrorCodeIntegrityFailure)
		}
		out.StateDigest = bootstrapPublicState(raw, "id", "name", "include", "exclude", "require", "is_default")
	case "bootstrap-app":
		if q.ResourceID == "" {
			for _, query := range []zt.AccessApplicationListParams{
				{AccountID: cf.F(q.AccountID), Name: cf.F(q.Bootstrap.Name), Exact: cf.F(true), PerPage: cf.F(int64(100))},
				{AccountID: cf.F(q.AccountID), Domain: cf.F(q.Hostname), Exact: cf.F(true), PerPage: cf.F(int64(100))},
			} {
				page, e := zt.NewAccessApplicationService(opts...).List(ctx, query)
				if e != nil {
					return out, e
				}
				if len(page.Result) != 0 {
					return out, ingress.Error(generated.ErrorCodeStateConflict)
				}
			}
			return bootstrapSnapshot(q, out), nil
		}
		r, e := zt.NewAccessApplicationService(opts...).Get(ctx, q.ResourceID, zt.AccessApplicationGetParams{AccountID: cf.F(q.AccountID)})
		if e != nil {
			return out, e
		}
		raw, err = bootstrapObject(r.JSON.RawJSON(), q.ResourceID, q.Bootstrap.Name)
		if err != nil || rawText(raw, "domain") != q.Hostname || rawText(raw, "type") != "self_hosted" || rawText(raw, "aud") == "" {
			return out, ingress.Error(generated.ErrorCodeIntegrityFailure)
		}
		out.StateDigest = bootstrapPublicState(raw, "id", "name", "domain", "type", "aud")
	case "bootstrap-policy":
		if len(q.AllowedGroupIDs) != 1 || q.AccessAppID == "" {
			return out, ingress.Error(generated.ErrorCodeInputInvalid)
		}
		if e := bootstrapAccessInputs(ctx, q, opts, false); e != nil {
			return out, e
		}
		if q.ResourceID == "" {
			page, e := zt.NewAccessApplicationPolicyService(opts...).List(ctx, q.AccessAppID, zt.AccessApplicationPolicyListParams{AccountID: cf.F(q.AccountID), PerPage: cf.F(int64(100))})
			if e != nil {
				return out, e
			}
			if len(page.Result) != 0 {
				return out, ingress.Error(generated.ErrorCodeStateConflict)
			}
			return bootstrapSnapshot(q, out), nil
		}
		r, e := zt.NewAccessApplicationPolicyService(opts...).Get(ctx, q.AccessAppID, q.ResourceID, zt.AccessApplicationPolicyGetParams{AccountID: cf.F(q.AccountID)})
		if e != nil {
			return out, e
		}
		raw, err = bootstrapObject(r.JSON.RawJSON(), q.ResourceID, q.Bootstrap.Name)
		if err != nil || !bootstrapPolicy(raw, q.AllowedGroupIDs[0]) {
			return out, ingress.Error(generated.ErrorCodeIntegrityFailure)
		}
		out.StateDigest = bootstrapPublicState(raw, "id", "name", "decision", "include", "exclude", "require", "precedence", "reusable", "app_count")
	case "bootstrap-seed":
		if q.TunnelID == "" || q.AccessPolicyID == "" {
			return out, ingress.Error(generated.ErrorCodeInputInvalid)
		}
		if e := bootstrapAccessInputs(ctx, q, opts, true); e != nil {
			return out, e
		}
		t, e := zt.NewTunnelCloudflaredService(opts...).Get(ctx, q.TunnelID, zt.TunnelCloudflaredGetParams{AccountID: cf.F(q.AccountID)})
		if e != nil {
			return out, e
		}
		tr, e := bootstrapObject(t.JSON.RawJSON(), q.TunnelID, q.Bootstrap.Name)
		if e != nil || rawText(tr, "config_src") != "cloudflare" {
			return out, ingress.Error(generated.ErrorCodeIntegrityFailure)
		}
		r, e := zt.NewTunnelCloudflaredConfigurationService(opts...).Get(ctx, q.TunnelID, zt.TunnelCloudflaredConfigurationGetParams{AccountID: cf.F(q.AccountID)})
		if e != nil {
			var apiErr *cf.Error
			if !errors.As(e, &apiErr) || apiErr.StatusCode != 404 || q.ResourceID != "" {
				return out, e
			}
			return bootstrapSnapshot(q, out), nil
		}
		config, e := rawObject(r.JSON.RawJSON())
		if e != nil || rawText(config, "tunnel_id") != q.TunnelID || rawText(config, "source") != "cloudflare" {
			return out, ingress.Error(generated.ErrorCodeIntegrityFailure)
		}
		out.Config, e = rawObject(string(config["config"]))
		if e != nil {
			return out, e
		}
		if !bootstrapConfigOwned(out.Config) {
			return out, ingress.Error(generated.ErrorCodeStateConflict)
		}
		var rules []map[string]json.RawMessage
		if v := out.Config["ingress"]; len(v) > 0 && json.Unmarshal(v, &rules) != nil {
			return out, ingress.Error(generated.ErrorCodeIntegrityFailure)
		}
		out.StateDigest = canonicalDigest(config["config"])
		if len(rules) == 0 || len(rules) == 1 && rawText(rules[0], "service") == "http_status:404" && len(rules[0]) == 1 {
			return bootstrapSnapshot(q, out), nil
		}
		expected, _ := json.Marshal(bootstrapRules(q))
		if canonicalDigest(out.Config["ingress"]) != canonicalDigest(expected) {
			return out, ingress.Error(generated.ErrorCodeStateConflict)
		}
		out.Present, out.ResourceID = true, q.TunnelID
		out.Hostname, out.OriginService, out.OriginServerName, out.OriginTLSVerified = q.Hostname, q.OriginService, q.OriginServerName, true
		return bootstrapSnapshot(q, out), nil
	case "bootstrap-cutover":
		if q.TunnelID == "" || q.AccessPolicyID == "" {
			return out, ingress.Error(generated.ErrorCodeInputInvalid)
		}
		if e := bootstrapAccessInputs(ctx, q, opts, true); e != nil {
			return out, e
		}
		if e := bootstrapServingConnector(ctx, q, opts); e != nil {
			return out, e
		}
		seed := q
		seed.Action, seed.ResourceKind, seed.ResourceID = "bootstrap-seed", "tunnel-configuration", q.TunnelID
		seed.Bootstrap = &generated.IngressBootstrap{Name: q.Bootstrap.Name, AllowedEmail: q.Bootstrap.AllowedEmail, OriginCAPool: q.Bootstrap.OriginCAPool, SourceRunIDs: q.Bootstrap.SourceRunIDs[:4]}
		ready, e := c.ObserveBootstrap(ctx, seed, v)
		if e != nil || !ready.Present {
			return out, ingress.Error(generated.ErrorCodePrerequisiteBlocked)
		}
		r, e := dns.NewRecordService(opts...).Get(ctx, q.DNSRecordID, dns.RecordGetParams{ZoneID: cf.F(q.ZoneID)})
		if e != nil {
			return out, e
		}
		raw, e = rawObject(r.JSON.RawJSON())
		if e != nil || rawText(raw, "id") != q.DNSRecordID || rawText(raw, "name") != q.Hostname || rawText(raw, "type") != "CNAME" {
			return out, ingress.Error(generated.ErrorCodeIntegrityFailure)
		}
		out.DNSName, out.DNSContent = q.Hostname, rawText(raw, "content")
		_ = json.Unmarshal(raw["proxied"], &out.DNSProxied)
		out.StateDigest = canonicalDigest(json.RawMessage(r.JSON.RawJSON()))
		out.Present, out.ResourceID = true, q.DNSRecordID
		return bootstrapSnapshot(q, out), nil
	default:
		return out, ingress.Error(generated.ErrorCodeInputInvalid)
	}
	out.Present, out.ResourceID = true, q.ResourceID
	return bootstrapSnapshot(q, out), nil
}

func bootstrapAccessInputs(ctx context.Context, q generated.IngressChange, opts []option.RequestOption, policy bool) error {
	if len(q.AllowedGroupIDs) != 1 || q.AccessAppID == "" {
		return ingress.Error(generated.ErrorCodeInputInvalid)
	}
	app, e := zt.NewAccessApplicationService(opts...).Get(ctx, q.AccessAppID, zt.AccessApplicationGetParams{AccountID: cf.F(q.AccountID)})
	if e != nil {
		return e
	}
	raw, e := bootstrapObject(app.JSON.RawJSON(), q.AccessAppID, q.Bootstrap.Name)
	if e != nil || rawText(raw, "domain") != q.Hostname || rawText(raw, "type") != "self_hosted" || rawText(raw, "aud") == "" {
		return ingress.Error(generated.ErrorCodeIntegrityFailure)
	}
	group, e := zt.NewAccessGroupService(opts...).Get(ctx, q.AllowedGroupIDs[0], zt.AccessGroupGetParams{AccountID: cf.F(q.AccountID)})
	if e != nil {
		return e
	}
	raw, e = bootstrapObject(group.JSON.RawJSON(), q.AllowedGroupIDs[0], q.Bootstrap.Name)
	if e != nil || !bootstrapGroup(raw, q.Bootstrap.AllowedEmail) {
		return ingress.Error(generated.ErrorCodeIntegrityFailure)
	}
	if !policy {
		return nil
	}
	page, e := zt.NewAccessApplicationPolicyService(opts...).List(ctx, q.AccessAppID, zt.AccessApplicationPolicyListParams{AccountID: cf.F(q.AccountID), PerPage: cf.F(int64(100))})
	if e != nil {
		return e
	}
	if len(page.Result) != 1 {
		return ingress.Error(generated.ErrorCodeIntegrityFailure)
	}
	raw, e = bootstrapObject(page.Result[0].JSON.RawJSON(), q.AccessPolicyID, q.Bootstrap.Name)
	if e != nil || !bootstrapPolicy(raw, q.AllowedGroupIDs[0]) {
		return ingress.Error(generated.ErrorCodeIntegrityFailure)
	}
	return nil
}

func bootstrapServingConnector(ctx context.Context, q generated.IngressChange, opts []option.RequestOption) error {
	connections, err := zt.NewTunnelCloudflaredConnectionService(opts...).Get(ctx, q.TunnelID, zt.TunnelCloudflaredConnectionGetParams{AccountID: cf.F(q.AccountID)})
	if err != nil {
		return err
	}
	if len(connections.Result) != 1 || connections.Result[0].ID != q.Connectors[0].ConnectorID || len(connections.Result[0].Conns) > 32 {
		return ingress.Error(generated.ErrorCodePrerequisiteBlocked)
	}
	for _, conn := range connections.Result[0].Conns {
		if conn.ClientID != "" && conn.ClientID != q.Connectors[0].ConnectorID {
			return ingress.Error(generated.ErrorCodeIntegrityFailure)
		}
		if !conn.IsPendingReconnect && conn.ID != "" && !conn.OpenedAt.IsZero() {
			return nil
		}
	}
	return ingress.Error(generated.ErrorCodePrerequisiteBlocked)
}

func (c *SDKClient) MutateBootstrap(ctx context.Context, q generated.IngressChange, read, write *credentialref.Value) (out ingress.Snapshot, err error) {
	if err = bootstrapInput(q); err != nil || q.ResourceID != "" {
		return out, ingress.Error(generated.ErrorCodeInputInvalid)
	}
	before, err := c.ObserveBootstrap(ctx, q, read)
	if err != nil {
		return out, err
	}
	if before.Digest != q.BeforeDigest {
		return out, ingress.Error(generated.ErrorCodePlanStale)
	}
	if q.Action != "bootstrap-cutover" && before.Present {
		return out, ingress.Error(generated.ErrorCodeStateConflict)
	}
	opts, err := c.options(write)
	if err != nil {
		return out, err
	}
	defer func() {
		if err != nil {
			err = ingress.Error(generated.ErrorCodeRecoveryRequired)
		}
	}()
	id := ""
	switch q.Action {
	case "bootstrap-tunnel":
		r, e := zt.NewTunnelCloudflaredService(opts...).New(ctx, zt.TunnelCloudflaredNewParams{AccountID: cf.F(q.AccountID), Name: cf.F(q.Bootstrap.Name), ConfigSrc: cf.F(zt.TunnelCloudflaredNewParamsConfigSrcCloudflare)})
		if e != nil {
			return out, e
		}
		id = r.ID
	case "bootstrap-group":
		r, e := zt.NewAccessGroupService(opts...).New(ctx, zt.AccessGroupNewParams{AccountID: cf.F(q.AccountID), Name: cf.F(q.Bootstrap.Name), IsDefault: cf.F(false), Include: cf.F([]zt.AccessRuleUnionParam{zt.EmailRuleParam{Email: cf.F(zt.EmailRuleEmailParam{Email: cf.F(q.Bootstrap.AllowedEmail)})}})})
		if e != nil {
			return out, e
		}
		id = r.ID
	case "bootstrap-app":
		r, e := zt.NewAccessApplicationService(opts...).New(ctx, zt.AccessApplicationNewParams{AccountID: cf.F(q.AccountID), Body: zt.AccessApplicationNewParamsBodySelfHostedApplication{Domain: cf.F(q.Hostname), Type: cf.F(zt.ApplicationTypeSelfHosted), Name: cf.F(q.Bootstrap.Name), SessionDuration: cf.F("1h"), HTTPOnlyCookieAttribute: cf.F(true), OptionsPreflightBypass: cf.F(false)}})
		if e != nil {
			return out, e
		}
		raw, e := rawObject(r.JSON.RawJSON())
		if e != nil {
			return out, e
		}
		id = rawText(raw, "id")
	case "bootstrap-policy":
		include := []zt.AccessRuleUnionParam{zt.GroupRuleParam{Group: cf.F(zt.GroupRuleGroupParam{ID: cf.F(q.AllowedGroupIDs[0])})}}
		r, e := zt.NewAccessApplicationPolicyService(opts...).New(ctx, q.AccessAppID, zt.AccessApplicationPolicyNewParams{AccountID: cf.F(q.AccountID), Precedence: cf.F(int64(0)), SessionDuration: cf.F("1h")}, option.WithJSONSet("name", q.Bootstrap.Name), option.WithJSONSet("decision", "allow"), option.WithJSONSet("include", include))
		if e != nil {
			return out, e
		}
		id = r.ID
	case "bootstrap-seed":
		_, e := zt.NewTunnelCloudflaredConfigurationService(opts...).Update(ctx, q.TunnelID, zt.TunnelCloudflaredConfigurationUpdateParams{AccountID: cf.F(q.AccountID)}, option.WithJSONSet("config", map[string]any{"ingress": bootstrapRules(q)}))
		if e != nil {
			return out, e
		}
		id = q.TunnelID
	case "bootstrap-cutover":
		readOpts, e := c.options(read)
		if e != nil {
			return out, e
		}
		r, e := dns.NewRecordService(readOpts...).Get(ctx, q.DNSRecordID, dns.RecordGetParams{ZoneID: cf.F(q.ZoneID)})
		if e != nil {
			return out, e
		}
		raw, e := rawObject(r.JSON.RawJSON())
		if e != nil || canonicalDigest(json.RawMessage(r.JSON.RawJSON())) != before.StateDigest {
			return out, ingress.Error(generated.ErrorCodePlanStale)
		}
		extra := []option.RequestOption{}
		for _, key := range []string{"comment", "tags", "settings"} {
			if v, ok := raw[key]; ok {
				var body any
				if json.Unmarshal(v, &body) != nil {
					return out, ingress.Error(generated.ErrorCodeIntegrityFailure)
				}
				extra = append(extra, option.WithJSONSet(key, body))
			}
		}
		_, e = dns.NewRecordService(opts...).Update(ctx, q.DNSRecordID, dns.RecordUpdateParams{ZoneID: cf.F(q.ZoneID), Body: dns.RecordUpdateParamsBody{Name: cf.F(q.Hostname), Type: cf.F(dns.RecordUpdateParamsBodyTypeCNAME), TTL: cf.F(dns.TTL(1)), Content: cf.F(q.TunnelID + ".cfargotunnel.com"), Proxied: cf.F(true)}}, extra...)
		if e != nil {
			return out, e
		}
		id = q.DNSRecordID
	default:
		return out, ingress.Error(generated.ErrorCodeInputInvalid)
	}
	if strings.TrimSpace(id) == "" {
		return out, ingress.Error(generated.ErrorCodeIntegrityFailure)
	}
	q.ResourceID = id
	if e := bootstrapInput(q); e != nil {
		return out, e
	}
	out, err = c.ObserveBootstrap(ctx, q, read)
	if err != nil {
		// A successful creation already returned this nonsecret ID. Preserve it
		// for reconciliation when subsequent observation is unavailable, without
		// claiming presence or accepting an unverified effect as successful.
		out.ResourceID = id
		out.Present = false
	}
	return out, err
}
