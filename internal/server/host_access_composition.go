package server

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	transport "github.com/vegastack/vegastack-labs/internal/adapter/hostaction"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/store"
	"slices"
)

type hostAccessComposition struct {
	store   *store.Store
	hosts   *store.HostActionRepository
	allowed []string
}

func (c hostAccessComposition) RenderRole(ctx context.Context, input generated.DebianAccessInput) (generated.RenderedAccess, error) {
	return transport.RenderRole(ctx, input)
}
func (c hostAccessComposition) ResolveLocalProbe(ctx context.Context, op adapter.Operation, b adapter.ExactExecutionBinding) (generated.HostActionRequest, generated.AccessProbeInput, error) {
	x, e := c.hosts.CurrentExecution(ctx, op, b)
	if e != nil {
		return generated.HostActionRequest{}, generated.AccessProbeInput{}, e
	}
	if x.Plan.HostAccessSequence == nil {
		return generated.HostActionRequest{}, generated.AccessProbeInput{}, actionFailure()
	}
	for _, target := range x.Plan.HostAccessSequence.AuxiliaryTargets {
		if !slices.Contains(c.allowed, target.IdentityDigest) {
			return generated.HostActionRequest{}, generated.AccessProbeInput{}, actionFailure()
		}
	}
	return c.hosts.ResolveAccessLocalProbe(ctx, x.Plan, op.OperationID)
}
func (c hostAccessComposition) RecordVerifiedControlResults(ctx context.Context, op adapter.Operation, b adapter.ExactExecutionBinding, effect adapter.Effect, result generated.HostActionResult) error {
	a, e := c.store.HostAccessRunAttribution(ctx, b.RunID)
	if e != nil {
		return e
	}
	return c.store.RecordHostControlResults(ctx, store.HostControlResultsRequest{Operation: op, Binding: b, Effect: effect, Result: result, Attribution: a})
}

var _ transport.AccessSequenceSource = hostAccessComposition{}
var _ transport.ControlResultRecorder = hostAccessComposition{}

func (c hostAccessComposition) RenderPolicy(ctx context.Context, input generated.DebianBaselineInput) (string, error) {
	return transport.RenderBaselineRole(ctx, input)
}
