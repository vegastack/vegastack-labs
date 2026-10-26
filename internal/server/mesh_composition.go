package server

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	cloud "github.com/vegastack/vegastack-labs/internal/adapter/cloudflare"
	"github.com/vegastack/vegastack-labs/internal/api"
	"github.com/vegastack/vegastack-labs/internal/change"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/gate"
	"github.com/vegastack/vegastack-labs/internal/generated"
	mesh "github.com/vegastack/vegastack-labs/internal/networkmesh"
	"github.com/vegastack/vegastack-labs/internal/result"
	"github.com/vegastack/vegastack-labs/internal/run"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/store"
	"slices"
	"time"
)

type meshAuthority struct {
	repository  *store.MeshRepository
	gates       *store.GateRepository
	credentials *store.CredentialRepository
	registry    *adapter.Registry
	build       result.BuildInfo
	proofs      gate.ProofRegistry
	backend     cloud.Backend
}

func (c *meshAuthority) check(ctx context.Context, d mesh.Staged) error {
	if e := c.repository.CheckCurrent(ctx, d); e != nil {
		return e
	}
	scope, e := c.gates.GetAppliedProfileScope(ctx)
	if e != nil || scope.RecoveryEpoch != d.Request.RecoveryEpoch || !slices.Contains(scope.Capabilities, "cloudflare.mesh") || !slices.Contains(scope.Capabilities, "credential.mesh.read") {
		return mesh.Error(generated.ErrorCodePrerequisiteBlocked)
	}
	resolved := gate.ResolvedScope{ProfileID: scope.ProfileID, ProfileVersion: scope.ProfileVersion, PolicyID: scope.PolicyID, PolicyVersion: scope.PolicyVersion, Capabilities: scope.Capabilities, StateRevision: scope.StateRevision, RecoveryEpoch: scope.RecoveryEpoch}
	for _, g := range []struct{ id, kind, subject string }{{"platform-safety", "site", "scope"}, {"G-005", "site", "scope"}, {"G-016", "adapter", mesh.AdapterID}} {
		if g.id == "G-005" && d.Request.Change.Mode == "foundation" {
			continue
		}
		if g.id == "G-016" && d.Request.Change.Action == "import" {
			continue
		}
		subject := gate.Subject{ID: g.subject, Kind: g.kind, ReleaseBuildID: c.build.ReleaseBuildID, ToolVersion: c.build.ToolVersion, StateRevision: d.Bindings[0].StateRevision}
		v, e := gate.Evaluate(ctx, c.gates, resolved, subject, g.id, time.Now().UTC(), c.proofs)
		if e != nil || v.Outcome != "passed" && v.Outcome != "not-applicable" {
			return mesh.Error(generated.ErrorCodePrerequisiteBlocked)
		}
		if v.Outcome == "not-applicable" && g.id == "platform-safety" {
			return mesh.Error(generated.ErrorCodePrerequisiteBlocked)
		}
	}
	return nil
}
func (c *meshAuthority) Resolve(ctx context.Context, op adapter.Operation, b adapter.ExactExecutionBinding) (mesh.Staged, error) {
	d, e := c.repository.Resolve(ctx, op, b)
	if e == nil {
		e = c.check(ctx, d)
	}
	return d, e
}
func (c *meshAuthority) BorrowRead(ctx context.Context, d mesh.Staged) (*credentialref.Value, error) {
	if e := c.check(ctx, d); e != nil {
		return nil, e
	}
	scope, e := c.gates.GetAppliedProfileScope(ctx)
	if e != nil {
		return nil, e
	}
	for _, b := range d.Bindings {
		if b.PurposeID != mesh.PurposeRead {
			continue
		}
		ref, e := c.credentials.GetReference(ctx, b.ReferenceID)
		if e != nil || ref.Status != "active" || ref.MaterialVersion != b.MaterialVersion || ref.ConsumerID != mesh.AdapterID || ref.PurposeID != mesh.PurposeRead || ref.TargetID != b.TargetID || ref.RecoveryEpoch != b.RecoveryEpoch || ref.ActivatedAt == nil || !slices.Contains(ref.VerifiedConsumerIDs, mesh.AdapterID) {
			return nil, mesh.Error(generated.ErrorCodePrerequisiteBlocked)
		}
		cap, e := c.registry.ResolveCredentialCapability(b.ResolverID, mesh.AdapterID, scope.ProfileID)
		if e != nil || !slices.Contains(scope.Capabilities, cap) {
			return nil, mesh.Error(generated.ErrorCodePrerequisiteBlocked)
		}
		resolver, e := c.registry.ResolveCredentialResolver(b.ResolverID, mesh.AdapterID, scope.ProfileID)
		if e != nil {
			return nil, e
		}
		v, e := resolver.Resolve(ctx, b)
		if e != nil {
			return nil, e
		}
		if v == nil || len(v.Bytes()) == 0 {
			if v != nil {
				v.Close()
			}
			return nil, mesh.Error(generated.ErrorCodePrerequisiteBlocked)
		}
		if e = c.check(ctx, d); e != nil {
			v.Close()
			return nil, e
		}
		return v, nil
	}
	return nil, mesh.Error(generated.ErrorCodePrerequisiteBlocked)
}
func (c *meshAuthority) Record(ctx context.Context, d mesh.Staged, b adapter.ExactExecutionBinding, s mesh.Snapshot, status string) error {
	return c.repository.Record(ctx, d, b, s, status)
}

type meshSecretGate struct {
	source   *meshAuthority
	fallback run.GateVerifier
}

func (g meshSecretGate) VerifySecretStep(ctx context.Context, p generated.Plan, op generated.PlanOperation) error {
	if op.AdapterID != mesh.AdapterID {
		if g.fallback == nil {
			return mesh.Error(generated.ErrorCodePrerequisiteBlocked)
		}
		return g.fallback.VerifySecretStep(ctx, p, op)
	}
	if p.AuthorizationBranch != "human" || p.ExecutorMode != "central" || len(p.Operations) != 1 || len(op.ArtifactDigest) != 71 {
		return mesh.Error(generated.ErrorCodePrerequisiteBlocked)
	}
	d, e := g.source.repository.GetStaged(ctx, "mesh-"+op.ArtifactDigest[7:39])
	if e != nil {
		return e
	}
	return g.source.check(ctx, d)
}
func registerMesh(ctx context.Context, app *api.Application, s *store.Store, registry *adapter.Registry, declarations *change.Service, factory *result.Factory, p serverconfig.Profile, build result.BuildInfo, databasePath string) (*meshAuthority, error) {
	repository := store.NewMeshRepository(s, p.MeshScopeDigests)
	source := &meshAuthority{repository: repository, gates: store.NewGateRepository(s), credentials: store.NewCredentialRepository(s), registry: registry, build: build, proofs: gate.NewProofRegistry(), backend: cloud.NewClient()}
	if e := composeMeshNative(ctx, p, databasePath, s, registry); e != nil {
		return nil, e
	}
	if e := registry.Register(mesh.AdapterID, &cloud.MeshAdapter{Authority: source, Backend: source.backend}); e != nil {
		return nil, e
	}
	if e := api.RegisterMeshOperations(app, api.MeshOperations{Repository: repository, Declarations: declarations, Credentials: source.credentials, Results: factory, Observe: source.Observe}); e != nil {
		return nil, e
	}
	return source, nil
}

func (c *meshAuthority) Observe(ctx context.Context, q generated.MeshDraftRequest) (generated.MeshStatusData, error) {
	d, e := c.repository.Preview(ctx, q)
	if e != nil {
		return generated.MeshStatusData{}, e
	}
	scope, e := c.gates.GetAppliedProfileScope(ctx)
	if e != nil || scope.RecoveryEpoch != q.RecoveryEpoch || !slices.Contains(scope.Capabilities, "cloudflare.mesh") || !slices.Contains(scope.Capabilities, "credential.mesh.read") {
		return generated.MeshStatusData{}, mesh.Error(generated.ErrorCodePrerequisiteBlocked)
	}
	b := d.Bindings[0]
	cap, e := c.registry.ResolveCredentialCapability(b.ResolverID, mesh.AdapterID, scope.ProfileID)
	if e != nil || !slices.Contains(scope.Capabilities, cap) {
		return generated.MeshStatusData{}, mesh.Error(generated.ErrorCodePrerequisiteBlocked)
	}
	resolver, e := c.registry.ResolveCredentialResolver(b.ResolverID, mesh.AdapterID, scope.ProfileID)
	if e != nil {
		return generated.MeshStatusData{}, e
	}
	v, e := resolver.Resolve(ctx, b)
	if e != nil {
		return generated.MeshStatusData{}, e
	}
	defer v.Close()
	if v == nil || len(v.Bytes()) == 0 {
		return generated.MeshStatusData{}, mesh.Error(generated.ErrorCodePrerequisiteBlocked)
	}
	if _, e = c.repository.Preview(ctx, q); e != nil {
		return generated.MeshStatusData{}, e
	}
	observation, e := c.backend.Observe(ctx, q.Change, v)
	if e != nil {
		return generated.MeshStatusData{}, e
	}
	if _, e = c.repository.Preview(ctx, q); e != nil {
		return generated.MeshStatusData{}, e
	}
	return generated.MeshStatusData{Schema: generated.SchemaIDMeshStatusData, SchemaVersion: "1.0.0", ProfileID: q.Change.ProfileID, Status: "observed", Reason: observation.Reason, ObservationDigest: observation.Digest, ObservedAt: time.Now().UTC().Format(time.RFC3339), OwnershipRevision: q.Change.ExpectedOwnershipRevision, StateRevision: q.ExpectedStateRevision, RecoveryEpoch: q.RecoveryEpoch}, nil
}
