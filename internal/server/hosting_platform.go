package server

import (
	"context"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/hostingplatform"
)

// PrepareHostingPlatform binds an ordinary host-action request to the protected
// selected component profile. It never executes a native command or provider call.
func (c *hostingLifecycleComposition) PrepareHostingPlatform(ctx context.Context, in generated.HostActionRequest) (generated.HostActionRequest, error) {
	if c == nil || !hostingplatform.IsAction(in.ActionID) || hostaction.ValidateRequest(in) != nil {
		return in, serviceFailure(generated.ErrorCodeInputInvalid)
	}
	var supplied hostingplatform.Input
	if json.Unmarshal([]byte(in.ActionInput), &supplied) != nil {
		return in, serviceFailure(generated.ErrorCodeInputInvalid)
	}
	matched := false
	for _, p := range c.profiles {
		q, e := c.repo.Prepare(ctx, generated.HostingLifecycleDraftRequest{Schema: generated.SchemaIDHostingLifecycleDraftRequest, SchemaVersion: "1.0.0", TargetID: p.TargetID, Action: "resources.apply", ExpectedStateRevision: in.ExpectedStateRevision, RecoveryEpoch: in.RecoveryEpoch, IdempotencyKey: in.IdempotencyKey, ReasonDigest: hostaction.Digest(in)})
		if e != nil {
			continue
		}
		conf, _, e := c.configuration(ctx, q)
		if e != nil {
			return in, e
		}
		if conf.Platform == nil || conf.Platform.HostID != in.HostID {
			continue
		}
		if matched || *conf.Platform != supplied || in.CredentialReferenceID != p.PlatformReferenceID || supplied.HostIdentityDigest != in.ConsoleConfirmation.HostIdentityDigest {
			return in, serviceFailure(generated.ErrorCodePlanStale)
		}
		if e = c.checkTargets(ctx, q, conf); e != nil {
			return in, e
		}
		matched = true
	}
	if !matched {
		return in, serviceFailure(generated.ErrorCodePrerequisiteBlocked)
	}
	return in, nil
}
