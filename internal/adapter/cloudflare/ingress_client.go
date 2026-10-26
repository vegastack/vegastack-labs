package cloudflare

import (
	"context"
	"encoding/base64"
	"encoding/json"
	cf "github.com/cloudflare/cloudflare-go/v7"
	"github.com/cloudflare/cloudflare-go/v7/dns"
	"github.com/cloudflare/cloudflare-go/v7/option"
	zt "github.com/cloudflare/cloudflare-go/v7/zero_trust"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	ingress "github.com/vegastack/vegastack-labs/internal/networkingress"
	"slices"
	"strings"
)

type IngressBackend interface {
	ObserveIngress(context.Context, generated.IngressChange, *credentialref.Value) (ingress.Snapshot, error)
	MutateIngress(context.Context, generated.IngressChange, *credentialref.Value, *credentialref.Value) error
}

func rawObject(s string) (map[string]json.RawMessage, error) {
	var out map[string]json.RawMessage
	if json.Unmarshal([]byte(s), &out) != nil || out == nil {
		return nil, ingress.Error(generated.ErrorCodeIntegrityFailure)
	}
	return out, nil
}
func rawText(m map[string]json.RawMessage, k string) string {
	var s string
	_ = json.Unmarshal(m[k], &s)
	return s
}
func rawSet(m map[string]json.RawMessage, k string, v any) { b, _ := json.Marshal(v); m[k] = b }
func canonicalDigest(raw json.RawMessage) string {
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return ""
	}
	return ingress.Digest(v)
}
func ingressDigest(c generated.IngressChange, s ingress.Snapshot) string {
	if c.ResourceKind == "connector" || c.ResourceKind == "tunnel-token" {
		return ingress.Digest([]any{s.StateDigest, s.Connections})
	}
	return ingress.Digest(s.StateDigest)
}
func (c *SDKClient) ObserveIngress(ctx context.Context, q generated.IngressChange, v *credentialref.Value) (out ingress.Snapshot, err error) {
	opts, e := c.options(v)
	if e != nil {
		return out, e
	}
	defer func() {
		if err != nil {
			err = ingress.Error(generated.ErrorCodeDependencyUnavailable)
		}
	}()
	out.Present = true
	out.Reason = "configuration-observed"
	connections, e := zt.NewTunnelCloudflaredConnectionService(opts...).Get(ctx, q.TunnelID, zt.TunnelCloudflaredConnectionGetParams{AccountID: cf.F(q.AccountID)})
	if e != nil {
		return out, e
	}
	declared := map[string]bool{}
	for _, x := range q.Connectors {
		declared[x.ConnectorID] = true
	}
	out.Connections = []ingress.Connection{}
	if len(connections.Result) > 16 {
		return out, ingress.Error(generated.ErrorCodeIntegrityFailure)
	}
	for _, client := range connections.Result {
		if !declared[client.ID] {
			return out, ingress.Error(generated.ErrorCodeAuthorizationDenied)
		}
		if len(client.Conns) > 32 {
			return out, ingress.Error(generated.ErrorCodeIntegrityFailure)
		}
		for _, conn := range client.Conns {
			if conn.ClientID != "" && conn.ClientID != client.ID {
				return out, ingress.Error(generated.ErrorCodeIntegrityFailure)
			}
			if conn.IsPendingReconnect {
				continue
			}
			if conn.ID == "" || conn.OpenedAt.IsZero() {
				return out, ingress.Error(generated.ErrorCodeIntegrityFailure)
			}
			out.Connections = append(out.Connections, ingress.Connection{ConnectorID: client.ID, ConnectionID: conn.ID, OpenedAt: conn.OpenedAt})
		}
	}
	slices.SortFunc(out.Connections, func(a, b ingress.Connection) int {
		return strings.Compare(a.ConnectorID+"/"+a.ConnectionID, b.ConnectorID+"/"+b.ConnectionID)
	})
	if len(out.Connections) == 0 {
		out.Reason = "all-connectors-unavailable"
	}
	switch q.ResourceKind {
	case "tunnel-configuration":
		r, e := zt.NewTunnelCloudflaredConfigurationService(opts...).Get(ctx, q.TunnelID, zt.TunnelCloudflaredConfigurationGetParams{AccountID: cf.F(q.AccountID)})
		if e != nil {
			return out, e
		}
		raw, e := rawObject(r.JSON.RawJSON())
		if e != nil || rawText(raw, "tunnel_id") != q.TunnelID || rawText(raw, "source") != "cloudflare" {
			return out, ingress.Error(generated.ErrorCodeIntegrityFailure)
		}
		out.Config, e = rawObject(string(raw["config"]))
		if e != nil {
			return out, e
		}
		out.StateDigest = canonicalDigest(raw["config"])
		var rules []map[string]json.RawMessage
		if json.Unmarshal(out.Config["ingress"], &rules) != nil || len(rules) == 0 || len(rules) > 128 {
			return out, ingress.Error(generated.ErrorCodeIntegrityFailure)
		}
		found := false
		for _, rule := range rules {
			if rawText(rule, "hostname") != q.Hostname {
				continue
			}
			if found || rawText(rule, "path") != "" {
				return out, ingress.Error(generated.ErrorCodePrerequisiteBlocked)
			}
			found = true
			out.Hostname = q.Hostname
			out.OriginService = rawText(rule, "service")
			origin, _ := rawObject(string(rule["originRequest"]))
			out.OriginServerName = rawText(origin, "originServerName")
			var insecure bool
			defaults, _ := rawObject(string(out.Config["originRequest"]))
			_ = json.Unmarshal(defaults["noTLSVerify"], &insecure)
			if value, ok := origin["noTLSVerify"]; ok {
				_ = json.Unmarshal(value, &insecure)
			}
			out.OriginTLSVerified = !insecure
		}
		out.Present = found
		// Transport configuration alone cannot make a route protected. Check the exact existing app/policy and DNS binding first.
		if e = verifyIngressAccessAndDNS(ctx, q, opts); e != nil {
			return out, e
		}
	case "access-policy":
		p, e := zt.NewAccessApplicationPolicyService(opts...).Get(ctx, q.AccessAppID, q.AccessPolicyID, zt.AccessApplicationPolicyGetParams{AccountID: cf.F(q.AccountID)})
		if e != nil {
			return out, e
		}
		out.Policy, e = rawObject(p.JSON.RawJSON())
		if e != nil || rawText(out.Policy, "id") != q.AccessPolicyID {
			return out, ingress.Error(generated.ErrorCodeIntegrityFailure)
		}
		out.StateDigest = canonicalDigest(json.RawMessage(p.JSON.RawJSON()))
		out.PolicyName = rawText(out.Policy, "name")
		_ = json.Unmarshal(out.Policy["precedence"], &out.Precedence)
		out.AllowedGroupIDs = policyGroupIDs(out.Policy)
		if e = verifyIngressApp(ctx, q, opts); e != nil {
			return out, e
		}
	case "dns-record":
		r, e := dns.NewRecordService(opts...).Get(ctx, q.DNSRecordID, dns.RecordGetParams{ZoneID: cf.F(q.ZoneID)})
		if e != nil {
			return out, e
		}
		raw, e := rawObject(r.JSON.RawJSON())
		if e != nil || rawText(raw, "id") != q.DNSRecordID || rawText(raw, "name") != q.Hostname || rawText(raw, "type") != "CNAME" {
			return out, ingress.Error(generated.ErrorCodeIntegrityFailure)
		}
		out.StateDigest = canonicalDigest(json.RawMessage(r.JSON.RawJSON()))
		out.DNSName = rawText(raw, "name")
		out.DNSContent = rawText(raw, "content")
		_ = json.Unmarshal(raw["proxied"], &out.DNSProxied)
	case "connector":
		out.Present = false
		for _, x := range out.Connections {
			if x.ConnectorID == q.ConnectorID {
				out.Present = true
			}
		}
		out.StateDigest = ingress.Digest([]string{q.AccountID, q.TunnelID, q.ConnectorID})
	case "tunnel-token":
		r, e := zt.NewTunnelCloudflaredService(opts...).Get(ctx, q.TunnelID, zt.TunnelCloudflaredGetParams{AccountID: cf.F(q.AccountID)})
		if e != nil {
			return out, e
		}
		raw, e := rawObject(r.JSON.RawJSON())
		if e != nil || rawText(raw, "id") != q.TunnelID {
			return out, ingress.Error(generated.ErrorCodeIntegrityFailure)
		}
		out.StateDigest = ingress.Digest([]string{q.AccountID, q.TunnelID})
	default:
		return out, ingress.Error(generated.ErrorCodeInputInvalid)
	}
	out.Digest = ingressDigest(q, out)
	return out, nil
}
func verifyIngressApp(ctx context.Context, q generated.IngressChange, opts []option.RequestOption) error {
	app, e := zt.NewAccessApplicationService(opts...).Get(ctx, q.AccessAppID, zt.AccessApplicationGetParams{AccountID: cf.F(q.AccountID)})
	if e != nil {
		return e
	}
	raw, e := rawObject(app.JSON.RawJSON())
	if e != nil || rawText(raw, "id") != q.AccessAppID || rawText(raw, "domain") != q.Hostname {
		return ingress.Error(generated.ErrorCodeAuthorizationDenied)
	}
	return nil
}
func policyGroupIDs(p map[string]json.RawMessage) []string {
	var includes []struct {
		Group struct {
			ID string `json:"id"`
		} `json:"group"`
	}
	if json.Unmarshal(p["include"], &includes) != nil {
		return nil
	}
	ids := []string{}
	for _, x := range includes {
		if x.Group.ID == "" {
			return nil
		}
		ids = append(ids, x.Group.ID)
	}
	slices.Sort(ids)
	return ids
}
func verifyIngressAccessAndDNS(ctx context.Context, q generated.IngressChange, opts []option.RequestOption) error {
	if e := verifyIngressApp(ctx, q, opts); e != nil {
		return e
	}
	p, e := zt.NewAccessApplicationPolicyService(opts...).Get(ctx, q.AccessAppID, q.AccessPolicyID, zt.AccessApplicationPolicyGetParams{AccountID: cf.F(q.AccountID)})
	if e != nil {
		return e
	}
	raw, e := rawObject(p.JSON.RawJSON())
	if e != nil || rawText(raw, "id") != q.AccessPolicyID || rawText(raw, "decision") != "allow" || len(policyGroupIDs(raw)) == 0 {
		return ingress.Error(generated.ErrorCodeAuthorizationDenied)
	}
	r, e := dns.NewRecordService(opts...).Get(ctx, q.DNSRecordID, dns.RecordGetParams{ZoneID: cf.F(q.ZoneID)})
	if e != nil {
		return e
	}
	record, e := rawObject(r.JSON.RawJSON())
	var proxied bool
	_ = json.Unmarshal(record["proxied"], &proxied)
	if e != nil || rawText(record, "name") != q.Hostname || rawText(record, "type") != "CNAME" || rawText(record, "content") != q.TunnelID+".cfargotunnel.com" || !proxied {
		return ingress.Error(generated.ErrorCodeAuthorizationDenied)
	}
	return nil
}
func (c *SDKClient) MutateIngress(ctx context.Context, q generated.IngressChange, v, replacement *credentialref.Value) (err error) {
	opts, e := c.options(v)
	if e != nil {
		return e
	}
	defer func() {
		if err != nil {
			err = ingress.Error(generated.ErrorCodeRecoveryRequired)
		}
	}()
	switch q.Action {
	case "connector-disconnect":
		if q.ConnectorID == "" {
			return ingress.Error(generated.ErrorCodeInputInvalid)
		}
		_, err = zt.NewTunnelCloudflaredConnectionService(opts...).Delete(ctx, q.TunnelID, zt.TunnelCloudflaredConnectionDeleteParams{AccountID: cf.F(q.AccountID), ClientID: cf.F(q.ConnectorID)})
	case "token-rotate":
		if replacement == nil {
			return ingress.Error(generated.ErrorCodePrerequisiteBlocked)
		}
		decoded, e := base64.StdEncoding.DecodeString(string(replacement.Bytes()))
		if e != nil || len(decoded) < 32 {
			return ingress.Error(generated.ErrorCodeInputInvalid)
		}
		for i := range decoded {
			decoded[i] = 0
		}
		_, err = zt.NewTunnelCloudflaredService(opts...).Edit(ctx, q.TunnelID, zt.TunnelCloudflaredEditParams{AccountID: cf.F(q.AccountID), TunnelSecret: cf.F(string(replacement.Bytes()))})
	case "tunnel-config-update":
		r, e := zt.NewTunnelCloudflaredConfigurationService(opts...).Get(ctx, q.TunnelID, zt.TunnelCloudflaredConfigurationGetParams{AccountID: cf.F(q.AccountID)})
		if e != nil {
			return e
		}
		raw, e := rawObject(r.JSON.RawJSON())
		if e != nil {
			return e
		}
		config, e := rawObject(string(raw["config"]))
		if e != nil {
			return e
		}
		before := ingress.Snapshot{StateDigest: canonicalDigest(raw["config"])}
		if ingressDigest(q, before) != q.BeforeDigest {
			return ingress.Error(generated.ErrorCodePlanStale)
		}
		var rules []map[string]json.RawMessage
		if json.Unmarshal(config["ingress"], &rules) != nil {
			return ingress.Error(generated.ErrorCodeIntegrityFailure)
		}
		matches := 0
		for _, rule := range rules {
			if rawText(rule, "hostname") != q.Hostname {
				continue
			}
			matches++
			origin, e := rawObject(string(rule["originRequest"]))
			if e != nil {
				origin = map[string]json.RawMessage{}
			}
			rawSet(origin, "originServerName", q.OriginServerName)
			rawSet(origin, "noTLSVerify", false)
			rawSet(rule, "originRequest", origin)
			rawSet(rule, "service", q.OriginService)
		}
		if matches != 1 {
			return ingress.Error(generated.ErrorCodePlanStale)
		}
		rawSet(config, "ingress", rules)
		_, err = zt.NewTunnelCloudflaredConfigurationService(opts...).Update(ctx, q.TunnelID, zt.TunnelCloudflaredConfigurationUpdateParams{AccountID: cf.F(q.AccountID)}, option.WithJSONSet("config", config))
	case "access-policy-update":
		p, e := zt.NewAccessApplicationPolicyService(opts...).Get(ctx, q.AccessAppID, q.AccessPolicyID, zt.AccessApplicationPolicyGetParams{AccountID: cf.F(q.AccountID)})
		if e != nil {
			return e
		}
		raw, e := rawObject(p.JSON.RawJSON())
		if e != nil {
			return e
		}
		var reusable bool
		var applicationCount int
		_ = json.Unmarshal(raw["reusable"], &reusable)
		_ = json.Unmarshal(raw["app_count"], &applicationCount)
		if reusable || applicationCount > 1 {
			return ingress.Error(generated.ErrorCodePrerequisiteBlocked)
		}
		if ingressDigest(q, ingress.Snapshot{StateDigest: canonicalDigest(json.RawMessage(p.JSON.RawJSON()))}) != q.BeforeDigest {
			return ingress.Error(generated.ErrorCodePlanStale)
		}
		include := []zt.AccessRuleUnionParam{}
		for _, id := range q.AllowedGroupIDs {
			include = append(include, zt.GroupRuleParam{Group: cf.F(zt.GroupRuleGroupParam{ID: cf.F(id)})})
		}
		requestOpts := []option.RequestOption{option.WithJSONSet("name", q.PolicyName), option.WithJSONSet("decision", "allow"), option.WithJSONSet("include", include)}
		for _, key := range []string{"exclude", "require", "session_duration", "approval_groups", "approval_required", "connection_rules", "isolation_required", "mfa_config", "purpose_justification_prompt", "purpose_justification_required"} {
			if value, ok := raw[key]; ok {
				var body any
				if json.Unmarshal(value, &body) != nil {
					return ingress.Error(generated.ErrorCodeIntegrityFailure)
				}
				requestOpts = append(requestOpts, option.WithJSONSet(key, body))
			}
		}
		_, err = zt.NewAccessApplicationPolicyService(opts...).Update(ctx, q.AccessAppID, q.AccessPolicyID, zt.AccessApplicationPolicyUpdateParams{AccountID: cf.F(q.AccountID), Precedence: cf.F(q.Precedence)}, requestOpts...)
	case "dns-record-update":
		r, e := dns.NewRecordService(opts...).Get(ctx, q.DNSRecordID, dns.RecordGetParams{ZoneID: cf.F(q.ZoneID)})
		if e != nil {
			return e
		}
		raw, e := rawObject(r.JSON.RawJSON())
		if e != nil || ingressDigest(q, ingress.Snapshot{StateDigest: canonicalDigest(json.RawMessage(r.JSON.RawJSON()))}) != q.BeforeDigest {
			return ingress.Error(generated.ErrorCodePlanStale)
		}
		extra := []option.RequestOption{}
		for _, k := range []string{"comment", "tags", "settings"} {
			if b, ok := raw[k]; ok {
				var body any
				json.Unmarshal(b, &body)
				extra = append(extra, option.WithJSONSet(k, body))
			}
		}
		_, err = dns.NewRecordService(opts...).Update(ctx, q.DNSRecordID, dns.RecordUpdateParams{ZoneID: cf.F(q.ZoneID), Body: dns.RecordUpdateParamsBody{Name: cf.F(q.Hostname), Type: cf.F(dns.RecordUpdateParamsBodyType("CNAME")), TTL: cf.F(dns.TTL(1)), Content: cf.F(q.TunnelID + ".cfargotunnel.com"), Proxied: cf.F(true)}}, extra...)
	default:
		return ingress.Error(generated.ErrorCodeInputInvalid)
	}
	return err
}
