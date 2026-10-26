package cloudflare

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	mesh "github.com/vegastack/vegastack-labs/internal/networkmesh"
	"slices"
	"sync"
)

type meshCompleted struct {
	staged    mesh.Staged
	binding   adapter.ExactExecutionBinding
	snapshot  mesh.Snapshot
	operation adapter.Operation
}
type MeshAdapter struct {
	Authority mesh.Authority
	Backend   Backend
	mu        sync.Mutex
	completed map[string]meshCompleted
}

func (a *MeshAdapter) Execute(context.Context, adapter.Operation) (adapter.Effect, error) {
	return adapter.Effect{}, mesh.Error(generated.ErrorCodePrerequisiteBlocked)
}
func (a *MeshAdapter) ExecuteBoundWithCredentials(ctx context.Context, op adapter.Operation, b adapter.ExactExecutionBinding, values []*credentialref.Value) (adapter.Effect, error) {
	if a == nil || a.Authority == nil || a.Backend == nil || adapter.ValidateOperation(op) != nil {
		return adapter.Effect{}, mesh.Error(generated.ErrorCodePrerequisiteBlocked)
	}
	d, e := a.Authority.Resolve(ctx, op, b)
	if e != nil {
		return adapter.Effect{}, e
	}
	c := d.Request.Change
	if len(values) != len(d.Bindings) || len(values) == 0 {
		return adapter.Effect{}, mesh.Error(generated.ErrorCodePrerequisiteBlocked)
	}
	readIndex, writeIndex := -1, -1
	for i, x := range d.Bindings {
		if x.PurposeID == mesh.PurposeRead {
			readIndex = i
		}
		if x.PurposeID == mesh.PurposeWrite {
			writeIndex = i
		}
	}
	if readIndex < 0 {
		return adapter.Effect{}, mesh.Error(generated.ErrorCodePrerequisiteBlocked)
	}
	before, e := a.Backend.Observe(ctx, c, values[readIndex])
	if e != nil {
		return adapter.Effect{}, e
	}
	if before.Digest != c.BeforeDigest || !before.Present {
		return adapter.Effect{}, mesh.Error(generated.ErrorCodePlanStale)
	}
	if c.ResourceKind == "registration" && (before.PhysicalDeviceID != c.PhysicalDeviceID || before.ProviderUserID != c.ProviderUserID || before.RegistrationID != c.ResourceID) {
		return adapter.Effect{}, mesh.Error(generated.ErrorCodeAuthorizationDenied)
	}
	if c.ResourceKind == "registration" && c.Action == "import" && before.VirtualIPv4 == "" {
		return adapter.Effect{}, mesh.Error(generated.ErrorCodePrerequisiteBlocked)
	}
	if c.Action == "profile-routing-update" && !preservesRoutes(before.Routes, c.Routes, c.MeshCIDR) {
		return adapter.Effect{}, mesh.Error(generated.ErrorCodeAuthorizationDenied)
	}
	// Repeat current authorization, ownership, gates and exact lease immediately before effect.
	if _, e = a.Authority.Resolve(ctx, op, b); e != nil {
		return adapter.Effect{}, e
	}
	after := before
	if c.Action != "import" {
		if writeIndex < 0 {
			return adapter.Effect{}, mesh.Error(generated.ErrorCodePrerequisiteBlocked)
		}
		if e = a.Backend.Mutate(ctx, c, values[writeIndex]); e != nil {
			after.Reason = "provider-effect-uncertain"
			after.Digest = mesh.Digest([]string{b.RunID, b.StepID, after.Reason})
			_ = a.Authority.Record(context.WithoutCancel(ctx), d, b, after, "partial")
			return adapter.Effect{Status: "partial", ResultDigest: after.Digest, Changed: true}, nil
		}
		after, e = a.Backend.Observe(ctx, c, values[readIndex])
		if e != nil || !matches(c, after) {
			after.Reason = "provider-verification-pending"
			after.Digest = mesh.Digest([]string{b.RunID, b.StepID, after.Reason})
			_ = a.Authority.Record(context.WithoutCancel(ctx), d, b, after, "partial")
			return adapter.Effect{Status: "partial", ResultDigest: after.Digest, Changed: true, EffectObserved: true}, nil
		}
	}
	result := mesh.Digest([]any{b.RunID, b.StepID, after.Digest})
	a.mu.Lock()
	if a.completed == nil {
		a.completed = map[string]meshCompleted{}
	}
	a.completed[result] = meshCompleted{d, b, after, op}
	a.mu.Unlock()
	return adapter.Effect{Status: "succeeded", ResultDigest: result, Changed: true, EffectObserved: true}, nil
}
func (a *MeshAdapter) Verify(ctx context.Context, op adapter.Operation, effect adapter.Effect) (adapter.Verification, error) {
	a.mu.Lock()
	done, ok := a.completed[effect.ResultDigest]
	delete(a.completed, effect.ResultDigest)
	a.mu.Unlock()
	if !ok || done.operation.OperationID != op.OperationID || done.operation.OperationType != op.OperationType || done.operation.AdapterID != op.AdapterID || done.operation.ExecutorID != op.ExecutorID || done.operation.TargetID != op.TargetID || done.operation.InputDigest != op.InputDigest || done.operation.ArtifactDigest != op.ArtifactDigest || done.operation.Idempotent != op.Idempotent || effect.Status != "succeeded" {
		return adapter.Verification{Digest: effect.ResultDigest}, mesh.Error(generated.ErrorCodeIntegrityFailure)
	}
	fail := func(e error) (adapter.Verification, error) {
		observation := done.snapshot
		observation.Reason = "provider-verification-incomplete"
		observation.Digest = mesh.Digest([]string{done.binding.RunID, done.binding.StepID, observation.Reason})
		_ = a.Authority.Record(context.WithoutCancel(ctx), done.staged, done.binding, observation, "partial")
		return adapter.Verification{Digest: effect.ResultDigest}, e
	}
	if _, e := a.Authority.Resolve(ctx, op, done.binding); e != nil {
		return fail(e)
	}
	value, e := a.Authority.BorrowRead(ctx, done.staged)
	if e != nil {
		return fail(e)
	}
	defer value.Close()
	observed, e := a.Backend.Observe(ctx, done.staged.Request.Change, value)
	if e != nil || observed.Digest != done.snapshot.Digest {
		return fail(mesh.Error(generated.ErrorCodeIntegrityFailure))
	}
	if e = a.Authority.Record(ctx, done.staged, done.binding, observed, "observed"); e != nil {
		return fail(e)
	}
	return adapter.Verification{Verified: true, Digest: effect.ResultDigest}, nil
}
func preservesRoutes(old, next []generated.MeshRoute, meshCIDR string) bool {
	a, b := []string{}, []string{}
	seen := map[string]bool{}
	for _, r := range old {
		if r.Address != meshCIDR {
			a = append(a, r.Address)
		}
	}
	for _, r := range next {
		if seen[r.Address] {
			return false
		}
		seen[r.Address] = true
		if r.Address != meshCIDR {
			b = append(b, r.Address)
		}
	}
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(a, b)
}
func matches(c generated.MeshChange, s mesh.Snapshot) bool {
	switch c.Action {
	case "registration-delete":
		return !s.Present
	case "profile-routing-update":
		a, b := []string{}, []string{}
		for _, r := range c.Routes {
			a = append(a, r.Address)
		}
		for _, r := range s.Routes {
			b = append(b, r.Address)
		}
		slices.Sort(a)
		slices.Sort(b)
		return slices.Equal(a, b)
	case "gateway-rule-update":
		return s.Present && s.RuleName == c.RuleName && s.RuleAction == c.RuleAction && s.Traffic == c.Traffic && s.Identity == c.RuleIdentity && s.Precedence == c.Precedence && s.Enabled == c.Enabled
	}
	return false
}

var _ adapter.BoundCredentialExecutor = (*MeshAdapter)(nil)
