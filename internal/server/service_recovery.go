package server

import (
	"context"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/adapter/harbor"
	"github.com/vegastack/vegastack-labs/internal/adapter/serviceruntime"
	"github.com/vegastack/vegastack-labs/internal/adapter/workloadrecovery"
	"github.com/vegastack/vegastack-labs/internal/backup"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/servicerecovery"
	"github.com/vegastack/vegastack-labs/internal/store"
	"net/http"
	"time"
)

type serviceRecoveryComposition struct {
	base       *serviceCatalogComposition
	repo       *store.ServiceRecoveryRepository
	profiles   map[string]generated.ServiceRecoveryProfile
	runner     backup.ResticRunner
	routeProof func(context.Context, generated.ServiceRecoveryProfile, generated.ServiceRecoveryRequest) error
}

func serviceRecoveryPolicies(p serverconfig.Profile) ([]servicerecovery.Policy, error) {
	profiles, e := serverconfig.FreezeServiceRecoveryProfiles(p.ServiceRecoveryProfiles)
	if e != nil {
		return nil, e
	}
	out := make([]servicerecovery.Policy, 0, len(profiles))
	for _, profile := range profiles {
		out = append(out, servicerecovery.Policy{Binding: profile.Binding, PlatformOwnerID: profile.PlatformOwnerID, TargetServiceID: profile.TargetServiceID})
	}
	return out, nil
}
func newServiceRecoveryComposition(p serverconfig.Profile, base *serviceCatalogComposition) (*serviceRecoveryComposition, error) {
	if base == nil || base.store == nil {
		return nil, servicerecovery.Invalid()
	}
	profiles, e := serverconfig.FreezeServiceRecoveryProfiles(p.ServiceRecoveryProfiles)
	if e != nil {
		return nil, e
	}
	c := &serviceRecoveryComposition{base: base, repo: store.NewServiceRecoveryRepository(base.store), profiles: map[string]generated.ServiceRecoveryProfile{}, runner: backup.NewResticRunner()}
	for _, profile := range profiles {
		c.profiles[profile.Binding.PolicyID] = profile
	}
	return c, nil
}
func (c *serviceRecoveryComposition) Prepare(ctx context.Context, d generated.ServiceRecoveryDraftRequest) (generated.ServiceRecoveryRequest, error) {
	return c.repo.Prepare(ctx, d)
}
func recoveryTarget(t store.ServiceRuntimeTarget) serviceruntime.Target {
	return serviceruntime.Target{HostID: t.HostID, HostIdentityDigest: t.HostIdentityDigest, Address: t.Address, User: t.User, HostKey: t.HostKey, ExpectedMachineIDDigest: t.ExpectedMachineIDDigest, Port: t.Port}
}
func sameRecoveryTarget(a, b store.ServiceRuntimeTarget) bool {
	a.StateRevision = 0
	b.StateRevision = 0
	return a == b
}
func (c *serviceRecoveryComposition) Recover(ctx context.Context, q generated.ServiceRecoveryRequest, actor identity.Principal, lease backup.WriterLease) (servicerecovery.Outcome, error) {
	ctx = identity.WithVerifiedPrincipal(ctx, actor)
	p, ok := c.profiles[q.Binding.PolicyID]
	if !ok || p.Binding != q.Binding {
		return servicerecovery.Outcome{}, servicerecovery.Blocked()
	}
	if e := c.repo.Authorize(ctx, q); e != nil {
		return servicerecovery.Outcome{}, e
	}
	source, e := c.sourceTarget(ctx, q)
	if e != nil {
		return servicerecovery.Outcome{}, e
	}
	targetDefinition, e := c.targetDefinition(ctx, q, p)
	if e != nil {
		return servicerecovery.Outcome{}, e
	}
	target, e := c.targetTarget(ctx, q, p, targetDefinition)
	if e != nil {
		return servicerecovery.Outcome{}, e
	}
	if source.HostID != p.Binding.SourceHostID || target.HostID != p.Binding.TargetHostID || source.RecoveryEpoch != q.RecoveryEpoch || target.RecoveryEpoch != q.RecoveryEpoch {
		return servicerecovery.Outcome{}, servicerecovery.Blocked()
	}
	// Use the same role/admission check as application mutation, for both exact
	// physical hosts. Registration is never substituted for admission evidence.
	for _, t := range []store.ServiceRuntimeTarget{source, target} {
		admission, e := (hostReplacementComposition{gates: c.base.gates, clock: time.Now}).roleAdmission(ctx, t.HostID)
		if e != nil {
			return servicerecovery.Outcome{}, e
		}
		if admission.IdentityDigest != t.HostIdentityDigest || admission.Revision.RecoveryEpoch != q.RecoveryEpoch || (admission.Profile.RoleID != "application" && admission.Profile.RoleID != "control") {
			return servicerecovery.Outcome{}, servicerecovery.Blocked()
		}
	}
	sourceKey, sourceIdentity, e := c.borrow(ctx, q, q.Definition.ServiceID, p.SourceReferenceID, "service.recovery", "workload-recovery", "credential.service-recovery.mutate")
	if e != nil {
		return servicerecovery.Outcome{}, e
	}
	defer sourceKey.Close()
	targetKey, targetIdentity, e := c.borrow(ctx, q, targetDefinition.ServiceID, p.TargetReferenceID, "service.recovery", "workload-recovery", "credential.service-recovery.mutate")
	if e != nil {
		return servicerecovery.Outcome{}, e
	}
	defer targetKey.Close()
	repositoryKey, repositoryIdentity, e := c.borrow(ctx, q, q.Definition.ServiceID, p.RepositoryKeyReferenceID, "service.recovery.repository", "workload-repository", "credential.service-recovery.repository")
	if e != nil {
		return servicerecovery.Outcome{}, e
	}
	defer repositoryKey.Close()
	check := func(checkCtx context.Context) error {
		if e := c.repo.Authorize(checkCtx, q); e != nil {
			return e
		}
		a, e := c.sourceTarget(checkCtx, q)
		if e != nil || !sameRecoveryTarget(a, source) {
			return servicerecovery.Blocked()
		}
		b, e := c.targetTarget(checkCtx, q, p, targetDefinition)
		if e != nil || !sameRecoveryTarget(b, target) {
			return servicerecovery.Blocked()
		}
		if e = c.recheck(checkCtx, q, q.Definition.ServiceID, p.SourceReferenceID, "service.recovery", "workload-recovery", "credential.service-recovery.mutate", sourceIdentity); e != nil {
			return e
		}
		if e = c.recheck(checkCtx, q, targetDefinition.ServiceID, p.TargetReferenceID, "service.recovery", "workload-recovery", "credential.service-recovery.mutate", targetIdentity); e != nil {
			return e
		}
		return c.recheck(checkCtx, q, q.Definition.ServiceID, p.RepositoryKeyReferenceID, "service.recovery.repository", "workload-repository", "credential.service-recovery.repository", repositoryIdentity)
	}
	previous, e := c.repo.BackupPoint(ctx, q)
	if e != nil {
		return servicerecovery.Outcome{}, e
	}
	lease.RepositoryID = p.RepositoryID
	if lease.PointID == "" {
		lease.PointID = "workload-point-" + servicerecovery.Digest(q)[7:39]
	}
	cfg := workloadrecovery.Config{Profile: p, Source: recoveryTarget(source), Target: recoveryTarget(target), SourceCredential: sourceKey, TargetCredential: targetKey, RepositoryKey: repositoryKey, Runner: c.runner, Check: check}
	if c.routeProof != nil {
		cfg.RouteProof = func(ctx context.Context) error { return c.routeProof(ctx, p, q) }
	}
	if p.Binding.DataClass == "registry" {
		cfg.VerifyRegistry = func(ctx context.Context, transport http.RoundTripper) (string, error) {
			if c.base.harborTransport != nil {
				transport = c.base.harborTransport
			}
			if e := check(ctx); e != nil {
				return "", e
			}
			key, ident, e := c.borrow(ctx, q, targetDefinition.ServiceID, p.HarborReferenceID, "registry.harbor", "registry-observe", "credential.registry.read")
			if e != nil {
				return "", e
			}
			defer key.Close()
			client, e := harbor.NewClient(p.HarborOrigin, transport)
			if e != nil {
				return "", e
			}
			snapshot, e := client.InspectArtifact(ctx, harbor.ArtifactTarget{Project: p.HarborProject, Repository: p.HarborRepository, Digest: p.HarborArtifactDigest}, p.HarborUsername, key)
			if e != nil {
				return "", e
			}
			if e = c.recheck(ctx, q, targetDefinition.ServiceID, p.HarborReferenceID, "registry.harbor", "registry-observe", "credential.registry.read", ident); e != nil {
				return "", e
			}
			// An exact authenticated artifact read proves catalog/digest access only.
			// Registry pull/denial behavior must also be observed by the typed verifier.
			proof, e := verifyRestoredRegistry(ctx, p, transport, key)
			if e != nil {
				return "", e
			}
			raw, _ := json.Marshal(snapshot)
			return servicerecovery.Digest([]string{servicerecovery.Digest(raw), proof}), check(ctx)
		}
	}
	return workloadrecovery.Execute(ctx, q, previous, lease, cfg)
}

func (c *serviceRecoveryComposition) sourceTarget(ctx context.Context, q generated.ServiceRecoveryRequest) (store.ServiceRuntimeTarget, error) {
	if q.Binding.DataClass == "platform" {
		return c.repo.HostRuntimeTarget(ctx, q.Binding.SourceHostID, q.Definition.HostIdentityDigest)
	}
	return c.base.repo.RuntimeTarget(ctx, q.Definition.ServiceID)
}
func (c *serviceRecoveryComposition) targetDefinition(ctx context.Context, q generated.ServiceRecoveryRequest, p generated.ServiceRecoveryProfile) (generated.ServiceDefinition, error) {
	if q.Binding.DataClass == "platform" {
		return c.repo.PlatformDefinition(ctx, q.Binding.PolicyID, true)
	}
	record, e := c.base.repo.Get(ctx, p.TargetServiceID)
	return record.Definition, e
}
func (c *serviceRecoveryComposition) targetTarget(ctx context.Context, q generated.ServiceRecoveryRequest, p generated.ServiceRecoveryProfile, d generated.ServiceDefinition) (store.ServiceRuntimeTarget, error) {
	if q.Binding.DataClass == "platform" {
		return c.repo.HostRuntimeTarget(ctx, p.Binding.TargetHostID, d.HostIdentityDigest)
	}
	return c.base.repo.RuntimeTarget(ctx, p.TargetServiceID)
}
