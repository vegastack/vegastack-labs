package cloudflare

import (
	"context"
	cf "github.com/cloudflare/cloudflare-go/v7"
	zt "github.com/cloudflare/cloudflare-go/v7/zero_trust"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	ingress "github.com/vegastack/vegastack-labs/internal/networkingress"
)

// ObservePilotAudience reads only the explicitly scoped existing application.
// It never discovers an account or touches an origin through the provider.
func (c *SDKClient) ObservePilotAudience(ctx context.Context, q generated.IngressChange, v *credentialref.Value) (string, error) {
	opts, e := c.options(v)
	if e != nil {
		return "", e
	}
	a, e := zt.NewAccessApplicationService(opts...).Get(ctx, q.AccessAppID, zt.AccessApplicationGetParams{AccountID: cf.F(q.AccountID)})
	if e != nil {
		return "", ingress.Error(generated.ErrorCodeDependencyUnavailable)
	}
	raw, e := rawObject(a.JSON.RawJSON())
	if e != nil || rawText(raw, "id") != q.AccessAppID || rawText(raw, "domain") != q.Hostname || rawText(raw, "aud") == "" {
		return "", ingress.Error(generated.ErrorCodePrerequisiteBlocked)
	}
	return rawText(raw, "aud"), nil
}
