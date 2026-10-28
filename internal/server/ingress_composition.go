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
	ingress "github.com/vegastack/vegastack-labs/internal/networkingress"
	"github.com/vegastack/vegastack-labs/internal/result"
	"github.com/vegastack/vegastack-labs/internal/run"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/store"
	"net/http"
	"slices"
	"time"
)

type ingressAuthority struct {
	pilot       *ingressPilotComposition
	repository  *store.IngressRepository
	gates       *store.GateRepository
	credentials *store.CredentialRepository
	registry    *adapter.Registry
	build       result.BuildInfo
	proofs      gate.ProofRegistry
	backend     cloud.IngressBackend
}

func (c *ingressAuthority) check(ctx context.Context, d ingress.Staged) error {
	if e := c.repository.CheckCurrent(ctx, d); e != nil {
		return e
	}
	scope, e := c.gates.GetAppliedProfileScope(ctx)
	if e != nil || scope.RecoveryEpoch != d.Request.RecoveryEpoch || !slices.Contains(scope.Capabilities, "cloudflare.ingress") || !slices.Contains(scope.Capabilities, "credential.ingress.read") {
		return ingress.Error(generated.ErrorCodePrerequisiteBlocked)
	}
	resolved := gate.ResolvedScope{ProfileID: scope.ProfileID, ProfileVersion: scope.ProfileVersion, PolicyID: scope.PolicyID, PolicyVersion: scope.PolicyVersion, Capabilities: scope.Capabilities, StateRevision: scope.StateRevision, RecoveryEpoch: scope.RecoveryEpoch}
	if c.pilot != nil {
		if !c.pilot.enabled(resolved) || ingress.ValidatePilotChange(*c.pilot.profile.IngressControllerReadPilot, d.Request.Change, d.Request.RecoveryEpoch) != nil {
			return ingress.Error(generated.ErrorCodePrerequisiteBlocked)
		}
		for _, id := range []string{"platform-safety", ingress.PilotGateID, "G-016"} {
			evaluation, err := c.pilot.evaluate(ctx, resolved, id, time.Now().UTC())
			if err != nil || evaluation.Outcome != "passed" {
				return ingress.Error(generated.ErrorCodePrerequisiteBlocked)
			}
		}
		return nil
	}

	for _, g := range []struct{ id, kind, subject string }{{"platform-safety", "site", "scope"}, {"G-012", "site", "scope"}, {"G-016", "adapter", ingress.AdapterID}} {
		if g.id == "G-012" && d.Request.Change.Action == "import" {
			continue
		}
		if g.id == "G-016" && d.Request.Change.Action == "import" {
			continue
		}
		subject := gate.Subject{ID: g.subject, Kind: g.kind, ReleaseBuildID: c.build.ReleaseBuildID, ToolVersion: c.build.ToolVersion, StateRevision: d.Bindings[0].StateRevision}
		v, e := gate.Evaluate(ctx, c.gates, resolved, subject, g.id, time.Now().UTC(), c.proofs)
		if e != nil || v.Outcome != "passed" && v.Outcome != "not-applicable" {
			return ingress.Error(generated.ErrorCodePrerequisiteBlocked)
		}
		if v.Outcome == "not-applicable" && g.id == "platform-safety" {
			return ingress.Error(generated.ErrorCodePrerequisiteBlocked)
		}
	}
	return nil
}
func (c *ingressAuthority) Resolve(ctx context.Context, op adapter.Operation, b adapter.ExactExecutionBinding) (ingress.Staged, error) {
	d, e := c.repository.Resolve(ctx, op, b)
	if e == nil {
		e = c.check(ctx, d)
	}
	return d, e
}
func (c *ingressAuthority) BorrowRead(ctx context.Context, d ingress.Staged) (*credentialref.Value, error) {
	if e := c.check(ctx, d); e != nil {
		return nil, e
	}
	scope, e := c.gates.GetAppliedProfileScope(ctx)
	if e != nil {
		return nil, e
	}
	for _, b := range d.Bindings {
		if b.PurposeID != ingress.PurposeRead {
			continue
		}
		ref, e := c.credentials.GetReference(ctx, b.ReferenceID)
		if e != nil || ref.Status != "active" || ref.MaterialVersion != b.MaterialVersion || ref.ConsumerID != ingress.AdapterID || ref.PurposeID != ingress.PurposeRead || ref.TargetID != b.TargetID || ref.RecoveryEpoch != b.RecoveryEpoch || ref.ActivatedAt == nil || !slices.Contains(ref.VerifiedConsumerIDs, ingress.AdapterID) {
			return nil, ingress.Error(generated.ErrorCodePrerequisiteBlocked)
		}
		cap, e := c.registry.ResolveCredentialCapability(b.ResolverID, ingress.AdapterID, scope.ProfileID)
		if e != nil || !slices.Contains(scope.Capabilities, cap) {
			return nil, ingress.Error(generated.ErrorCodePrerequisiteBlocked)
		}
		resolver, e := c.registry.ResolveCredentialResolver(b.ResolverID, ingress.AdapterID, scope.ProfileID)
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
			return nil, ingress.Error(generated.ErrorCodePrerequisiteBlocked)
		}
		if e = c.check(ctx, d); e != nil {
			v.Close()
			return nil, e
		}
		return v, nil
	}
	return nil, ingress.Error(generated.ErrorCodePrerequisiteBlocked)
}
func (c *ingressAuthority) Record(ctx context.Context, d ingress.Staged, b adapter.ExactExecutionBinding, s ingress.Snapshot, status string) error {
	return c.repository.Record(ctx, d, b, s, status)
}

type ingressSecretGate struct {
	source   *ingressAuthority
	fallback run.GateVerifier
}

func (g ingressSecretGate) VerifySecretStep(ctx context.Context, p generated.Plan, op generated.PlanOperation) error {
	if op.AdapterID != ingress.AdapterID {
		if g.fallback == nil {
			return ingress.Error(generated.ErrorCodePrerequisiteBlocked)
		}
		return g.fallback.VerifySecretStep(ctx, p, op)
	}
	if p.AuthorizationBranch != "human" || p.ExecutorMode != "central" || len(p.Operations) != 1 || len(op.ArtifactDigest) != 71 {
		return ingress.Error(generated.ErrorCodePrerequisiteBlocked)
	}
	d, e := g.source.repository.GetStaged(ctx, "ingress-"+op.ArtifactDigest[7:39])
	if e != nil {
		return e
	}
	return g.source.check(ctx, d)
}
func registerIngress(ctx context.Context, app *api.Application, s *store.Store, registry *adapter.Registry, declarations *change.Service, factory *result.Factory, p serverconfig.Profile, build result.BuildInfo, databasePath string, identityClient *http.Client) (*ingressAuthority, error) {
	repository := store.NewIngressRepository(s, p.IngressScopeDigests)
	source := &ingressAuthority{repository: repository, gates: store.NewGateRepository(s), credentials: store.NewCredentialRepository(s), registry: registry, build: build, proofs: gate.NewProofRegistry(), backend: cloud.NewClient()}
	if p.IngressControllerReadPilot != nil {
		source.pilot = &ingressPilotComposition{profile: p, store: s, source: source, identityClient: identityClient, probe: probePilotOrigin, machine: pilotMachineDigest}
	}
	if e := composeIngressNative(ctx, p, databasePath, s, registry); e != nil {
		return nil, e
	}
	if e := registry.Register(ingress.AdapterID, &cloud.IngressAdapter{Authority: source, Backend: source.backend}); e != nil {
		return nil, e
	}
	if e := api.RegisterIngressOperations(app, api.IngressOperations{Repository: repository, Declarations: declarations, Credentials: source.credentials, Results: factory, Observe: source.Observe, Rollout: source.Rollout, PilotEvidence: source.CollectPilotEvidence, Revisions: store.NewPlanRepository(s)}); e != nil {
		return nil, e
	}
	return source, nil
}

func (c *ingressAuthority) Observe(ctx context.Context, q generated.IngressDraftRequest) (generated.IngressStatusData, error) {
	if c.pilot != nil && ingress.ValidatePilotChange(*c.pilot.profile.IngressControllerReadPilot, q.Change, q.RecoveryEpoch) != nil {
		return generated.IngressStatusData{}, ingress.Error(generated.ErrorCodeAuthorizationDenied)
	}
	d, e := c.repository.Preview(ctx, q)
	if e != nil {
		return generated.IngressStatusData{}, e
	}
	scope, e := c.gates.GetAppliedProfileScope(ctx)
	if e != nil || scope.RecoveryEpoch != q.RecoveryEpoch || !slices.Contains(scope.Capabilities, "cloudflare.ingress") || !slices.Contains(scope.Capabilities, "credential.ingress.read") {
		return generated.IngressStatusData{}, ingress.Error(generated.ErrorCodePrerequisiteBlocked)
	}
	b := d.Bindings[0]
	cap, e := c.registry.ResolveCredentialCapability(b.ResolverID, ingress.AdapterID, scope.ProfileID)
	if e != nil || !slices.Contains(scope.Capabilities, cap) {
		return generated.IngressStatusData{}, ingress.Error(generated.ErrorCodePrerequisiteBlocked)
	}
	resolver, e := c.registry.ResolveCredentialResolver(b.ResolverID, ingress.AdapterID, scope.ProfileID)
	if e != nil {
		return generated.IngressStatusData{}, e
	}
	v, e := resolver.Resolve(ctx, b)
	if e != nil {
		return generated.IngressStatusData{}, e
	}
	if v == nil || len(v.Bytes()) == 0 {
		return generated.IngressStatusData{}, ingress.Error(generated.ErrorCodePrerequisiteBlocked)
	}
	defer v.Close()
	if _, e = c.repository.Preview(ctx, q); e != nil {
		return generated.IngressStatusData{}, e
	}
	observation, e := c.backend.ObserveIngress(ctx, q.Change, v)
	if e != nil {
		return generated.IngressStatusData{}, e
	}
	if _, e = c.repository.Preview(ctx, q); e != nil {
		return generated.IngressStatusData{}, e
	}
	return generated.IngressStatusData{Schema: generated.SchemaIDIngressStatusData, SchemaVersion: "1.0.0", ProfileID: q.Change.ProfileID, RotationStage: "not-requested", Connectivity: "unknown", OriginIsolation: "unknown", Status: "observed", Reason: observation.Reason, ObservationDigest: observation.Digest, ObservedAt: time.Now().UTC().Format(time.RFC3339), OwnershipRevision: q.Change.ExpectedOwnershipRevision, StateRevision: q.ExpectedStateRevision, RecoveryEpoch: q.RecoveryEpoch}, nil
}

func (c *ingressAuthority) Rollout(ctx context.Context, q generated.IngressRolloutEvidenceRequest) (generated.IngressStatusData, error) {
	if c.pilot != nil {
		return generated.IngressStatusData{}, ingress.Error(generated.ErrorCodeAuthorizationDenied)
	}
	d, state, e := c.repository.Rotation(ctx, q)
	if e != nil {
		return generated.IngressStatusData{}, e
	}
	request := d.Request
	request.ExpectedStateRevision = q.ExpectedStateRevision
	request.RecoveryEpoch = q.RecoveryEpoch
	preview, e := c.repository.Preview(ctx, request)
	if e != nil {
		return generated.IngressStatusData{}, e
	}
	scope, e := c.gates.GetAppliedProfileScope(ctx)
	if e != nil || scope.RecoveryEpoch != q.RecoveryEpoch || !slices.Contains(scope.Capabilities, "cloudflare.ingress") {
		return generated.IngressStatusData{}, ingress.Error(generated.ErrorCodePrerequisiteBlocked)
	}
	binding := preview.Bindings[0]
	cap, e := c.registry.ResolveCredentialCapability(binding.ResolverID, ingress.AdapterID, scope.ProfileID)
	if e != nil || !slices.Contains(scope.Capabilities, cap) {
		return generated.IngressStatusData{}, ingress.Error(generated.ErrorCodePrerequisiteBlocked)
	}
	resolver, e := c.registry.ResolveCredentialResolver(binding.ResolverID, ingress.AdapterID, scope.ProfileID)
	if e != nil {
		return generated.IngressStatusData{}, e
	}
	value, e := resolver.Resolve(ctx, binding)
	if e != nil {
		return generated.IngressStatusData{}, e
	}
	if value == nil || len(value.Bytes()) == 0 {
		if value != nil {
			value.Close()
		}
		return generated.IngressStatusData{}, ingress.Error(generated.ErrorCodePrerequisiteBlocked)
	}
	defer value.Close()
	observed, e := c.backend.ObserveIngress(ctx, request.Change, value)
	if e != nil {
		return generated.IngressStatusData{}, e
	}
	if _, e = c.repository.Preview(ctx, request); e != nil {
		return generated.IngressStatusData{}, e
	}
	result := ingress.EvaluateRotation(state, ingress.RotationObservation{Connections: observed.Connections, Complete: true})
	out := generated.IngressStatusData{Schema: generated.SchemaIDIngressStatusData, SchemaVersion: "1.0.0", ProfileID: q.ProfileID, Status: "partial", Reason: result.Reason, ObservationDigest: observed.Digest, ObservedAt: time.Now().UTC().Format(time.RFC3339), OwnershipRevision: request.Change.ExpectedOwnershipRevision, StateRevision: q.ExpectedStateRevision, RecoveryEpoch: q.RecoveryEpoch, RotationStage: result.Stage, Connectivity: "unknown", OriginIsolation: "unknown"}
	if e = c.repository.RecordRollout(ctx, q, out); e != nil {
		return generated.IngressStatusData{}, e
	}
	return out, nil
}
