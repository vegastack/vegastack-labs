package server

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter/coolify"
	"github.com/vegastack/vegastack-labs/internal/adapter/serviceruntime"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/release"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/servicecatalog"
	"github.com/vegastack/vegastack-labs/internal/store"
)

// serviceDeploymentComposition extends the existing service credential and
// authorization path. Every provider target remains protected configuration.
type serviceDeploymentComposition struct {
	base     *serviceCatalogComposition
	repo     *store.DeploymentRepository
	bindings map[string]generated.ServiceDeploymentProviderBinding
	owner    uint32
	runtime  serviceruntime.Observer
}

func deploymentArtifact(ctx context.Context, a generated.ServiceDeploymentArtifactSource, owner uint32) (generated.ServiceDeploymentArtifact, error) {
	manifest, err := readLocalSetupProtected(ctx, a.ManifestPath, owner, 1<<20)
	if err != nil {
		return generated.ServiceDeploymentArtifact{}, err
	}
	bundle, err := readLocalSetupProtected(ctx, a.BundlePath, owner, 4<<20)
	if err != nil {
		return generated.ServiceDeploymentArtifact{}, err
	}
	policy, err := readLocalSetupProtected(ctx, a.PolicyPath, owner, 1<<20)
	if err != nil {
		return generated.ServiceDeploymentArtifact{}, err
	}
	proof, err := release.VerifyOCIBytes(ctx, manifest, bundle, policy, a.Digest)
	if err != nil {
		return generated.ServiceDeploymentArtifact{}, err
	}
	return generated.ServiceDeploymentArtifact{Schema: generated.SchemaIDServiceDeploymentArtifact, SchemaVersion: "1.0.0", ArtifactID: a.ArtifactID, Repository: a.Repository, Digest: a.Digest, ManifestSHA: proof.ManifestDigest, BundleSHA: proof.BundleDigest, PolicySHA: proof.PolicyDigest}, nil
}
func deploymentPolicies(ctx context.Context, p serverconfig.Profile) ([]servicecatalog.DeploymentPolicy, error) {
	bindings, err := serverconfig.FreezeDeploymentBindings(p.ServiceDeploymentBindings, p.ServiceBindings)
	if err != nil {
		return nil, err
	}
	out := make([]servicecatalog.DeploymentPolicy, 0, len(bindings))
	for _, b := range bindings {
		policy := servicecatalog.DeploymentPolicy{Binding: b.Binding, Configuration: b.Configuration, EnvironmentBindings: b.EnvironmentSecrets}
		for _, source := range b.Artifacts {
			a, err := deploymentArtifact(ctx, source, p.SocketOwnerUID)
			if err != nil {
				return nil, err
			}
			policy.Artifacts = append(policy.Artifacts, a)
		}
		out = append(out, policy)
	}
	return out, nil
}
func newServiceDeploymentComposition(p serverconfig.Profile, base *serviceCatalogComposition) (*serviceDeploymentComposition, error) {
	if base == nil || base.store == nil {
		return nil, serviceFailure(generated.ErrorCodeInputInvalid)
	}
	bindings, err := serverconfig.FreezeDeploymentBindings(p.ServiceDeploymentBindings, p.ServiceBindings)
	if err != nil {
		return nil, err
	}
	c := &serviceDeploymentComposition{base: base, repo: store.NewDeploymentRepository(base.store), owner: p.SocketOwnerUID, bindings: map[string]generated.ServiceDeploymentProviderBinding{}, runtime: serviceruntime.NewClient()}
	for _, b := range bindings {
		c.bindings[b.Binding.ServiceID] = b
	}
	return c, nil
}
func (c *serviceDeploymentComposition) binding(q generated.ServiceDeploymentRequest) (generated.ServiceDeploymentProviderBinding, error) {
	b, ok := c.bindings[q.Definition.ServiceID]
	if !ok || b.Binding != q.Binding || servicecatalog.Digest(b.EnvironmentSecrets) != servicecatalog.Digest(q.EnvironmentBindings) || b.ServiceBindingID != q.Definition.BindingID || !b.ExclusiveOwnership {
		return b, serviceFailure(generated.ErrorCodePlanStale)
	}
	if _, err := c.base.binding(q.Definition); err != nil {
		return b, err
	}
	return b, nil
}
func (c *serviceDeploymentComposition) artifact(ctx context.Context, q generated.ServiceDeploymentRequest, b generated.ServiceDeploymentProviderBinding) error {
	for _, source := range b.Artifacts {
		if source.ArtifactID == q.Artifact.ArtifactID {
			a, err := deploymentArtifact(ctx, source, c.owner)
			if err != nil {
				return err
			}
			if a != q.Artifact || q.ArtifactProofDigest != servicecatalog.Digest(a) {
				return serviceFailure(generated.ErrorCodePlanStale)
			}
			return nil
		}
	}
	return serviceFailure(generated.ErrorCodePrerequisiteBlocked)
}
func (c *serviceDeploymentComposition) authority(ctx context.Context, q generated.ServiceDeploymentRequest, initial *store.ServiceRuntimeTarget, preparing ...bool) (store.ServiceRuntimeTarget, error) {
	if _, err := c.binding(q); err != nil {
		return store.ServiceRuntimeTarget{}, err
	}
	if err := c.repo.AuthorizeConfiguration(ctx, q, len(preparing) > 0); err != nil {
		return store.ServiceRuntimeTarget{}, err
	}
	if _, err := c.base.check(ctx, q.Definition, false, q.RecoveryEpoch); err != nil {
		return store.ServiceRuntimeTarget{}, err
	}
	target, err := c.base.repo.RuntimeTarget(ctx, q.Definition.ServiceID)
	if err != nil {
		return target, err
	}
	if target.RecoveryEpoch != q.RecoveryEpoch || target.HostIdentityDigest != q.Definition.HostIdentityDigest {
		return target, serviceFailure(generated.ErrorCodePlanStale)
	}
	if initial != nil {
		before, after := *initial, target
		before.StateRevision = 0
		after.StateRevision = 0
		if before != after {
			return target, serviceFailure(generated.ErrorCodePlanStale)
		}
	}
	// Registration is deliberately not admission. Reuse the existing complete
	// evaluator rather than interpreting a snapshot or doc as a passed gate.
	admission, err := (hostReplacementComposition{gates: c.base.gates, clock: time.Now}).roleAdmission(ctx, q.Definition.HostID)
	if err != nil {
		return target, err
	}
	if q.Configuration != nil {
		if err := c.checkDataContract(ctx, q); err != nil {
			return target, err
		}
	}
	if admission.IdentityDigest != q.Definition.HostIdentityDigest || admission.Revision.RecoveryEpoch != q.RecoveryEpoch || admission.Profile.RoleID != "application" {
		return target, serviceFailure(generated.ErrorCodePrerequisiteBlocked)
	}
	return target, nil
}
func (c *serviceDeploymentComposition) Prepare(ctx context.Context, d generated.ServiceDeploymentDraftRequest) (generated.ServiceDeploymentRequest, error) {
	q, err := c.repo.Prepare(ctx, d)
	if err != nil {
		return q, err
	}
	b, err := c.binding(q)
	if err != nil {
		return q, err
	}
	if b.Configuration == nil {
		return q, serviceFailure(generated.ErrorCodePrerequisiteBlocked)
	}
	q.ArtifactProofDigest = servicecatalog.Digest(q.Artifact)
	if err = c.artifact(ctx, q, b); err != nil {
		return q, err
	}
	if _, err = c.authority(ctx, q, nil, true); err != nil {
		return q, err
	}
	if q.Configuration != nil {
		capacity, e := c.observeCapacity(ctx, q.Definition, b)
		if e != nil {
			return q, e
		}
		q.Capacity = &capacity
		if err = c.repo.Authorize(ctx, q); err != nil {
			return q, err
		}
	}
	return q, nil
}
func (c *serviceDeploymentComposition) Deploy(ctx context.Context, q generated.ServiceDeploymentRequest, actor identity.Principal) (out servicecatalog.DeploymentOutcome, err error) {
	out.Status = "partial"
	if !identity.ValidPrincipal(actor) {
		return out, serviceFailure(generated.ErrorCodeAuthenticationRequired)
	}
	ctx = identity.WithVerifiedPrincipal(ctx, actor)
	// The existing executor lease is 60 seconds. Reads and convergence are bounded
	// inside that lease; no additional worker or detached provider retry exists.
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	b, err := c.binding(q)
	if err != nil {
		return out, err
	}
	if b.Configuration == nil {
		return out, serviceFailure(generated.ErrorCodePrerequisiteBlocked)
	}
	target, err := c.authority(ctx, q, nil)
	if err != nil {
		return out, err
	}
	if err = c.artifact(ctx, q, b); err != nil {
		return out, err
	}
	service, err := c.base.binding(q.Definition)
	if err != nil || service.Coolify == nil || service.Harbor == nil {
		return out, serviceFailure(generated.ErrorCodePrerequisiteBlocked)
	}
	// Independently require this exact signed image to exist in the bound registry.
	h := *service.Harbor
	h.ArtifactDigest = q.Artifact.Digest
	artifact, _, err := c.base.artifact(ctx, q.Definition, false, q.RecoveryEpoch, h)
	if err != nil {
		return out, err
	}
	if artifact.Kind != "image" || artifact.Digest != q.Artifact.Digest {
		return out, serviceFailure(generated.ErrorCodeEvidenceInvalid)
	}
	value, credential, err := c.base.borrow(ctx, q.Definition, false, q.RecoveryEpoch, b.MutationReferenceID, "hosting.coolify.deploy", "hosting-deploy", "credential.hosting.deploy")
	if err != nil {
		return out, err
	}
	defer value.Close()
	runtimeValue, runtimeCredential, err := c.base.borrow(ctx, q.Definition, false, q.RecoveryEpoch, b.RuntimeReferenceID, "service.runtime", "runtime-observe", "credential.service-runtime.read")
	if err != nil {
		return out, err
	}
	defer runtimeValue.Close()
	environment := make([]coolify.EnvironmentValue, 0, len(b.EnvironmentSecrets))
	environmentIdentities := make([]serviceCredentialIdentity, 0, len(b.EnvironmentSecrets))
	environmentProof := make([]serviceruntime.EnvironmentFingerprint, 0, len(b.EnvironmentSecrets))
	environmentValues := make([]*credentialref.Value, 0, len(b.EnvironmentSecrets))
	defer func() {
		for _, value := range environmentValues {
			value.Close()
		}
	}()
	for _, secret := range b.EnvironmentSecrets {
		value, identity, e := c.base.borrow(ctx, q.Definition, false, q.RecoveryEpoch, secret.ReferenceID, "service.environment", "workload-env", "credential.service-environment.read")
		if e != nil {
			return out, e
		}
		environmentValues = append(environmentValues, value)
		if identity.Fingerprint != secret.ExpectedFingerprint {
			return out, serviceFailure(generated.ErrorCodePlanStale)
		}
		environment = append(environment, coolify.EnvironmentValue{Name: secret.Name, Value: value})
		environmentIdentities = append(environmentIdentities, identity)
		environmentProof = append(environmentProof, serviceruntime.EnvironmentFingerprint{Name: secret.Name, Digest: serviceruntime.EnvironmentDigest(secret.Name, value.Bytes())})
	}
	check := func(ctx context.Context) error {
		if _, err := c.authority(ctx, q, &target); err != nil {
			return err
		}
		if err := c.base.recheckCredential(ctx, q.Definition, false, q.RecoveryEpoch, b.MutationReferenceID, "hosting.coolify.deploy", "hosting-deploy", "credential.hosting.deploy", credential); err != nil {
			return err
		}
		for i, secret := range b.EnvironmentSecrets {
			if e := c.base.recheckCredential(ctx, q.Definition, false, q.RecoveryEpoch, secret.ReferenceID, "service.environment", "workload-env", "credential.service-environment.read", environmentIdentities[i]); e != nil {
				return e
			}
		}
		return c.base.recheckCredential(ctx, q.Definition, false, q.RecoveryEpoch, b.RuntimeReferenceID, "service.runtime", "runtime-observe", "credential.service-runtime.read", runtimeCredential)
	}
	if err = check(ctx); err != nil {
		return out, err
	}
	client, err := coolify.NewClient(service.Coolify.Origin, c.base.coolifyTransport)
	if err != nil {
		return out, err
	}
	cb := service.Coolify
	var settings *coolify.ImageSettings
	if q.Configuration != nil {
		mapped, e := coolify.Settings(*q.Configuration)
		if e != nil {
			return out, e
		}
		settings = &mapped
		actual, e := c.observeCapacity(ctx, q.Definition, b)
		if e != nil {
			return out, e
		}
		if e = c.repo.CheckPlacement(ctx, q.Definition, *q.Configuration, actual); e != nil {
			return out, e
		}
	}
	receipt, err := client.DeployImage(ctx, coolify.ImageDeploymentRequest{Environment: environment, Settings: settings, Target: coolify.ApplicationTarget{TeamID: cb.TeamID, ProjectID: cb.ProjectID, EnvironmentID: cb.EnvironmentID, DestinationID: cb.DestinationID, ProjectUUID: cb.ProjectUUID, Environment: cb.Environment, ApplicationUUID: cb.ApplicationUUID, DestinationType: cb.DestinationType}, DestinationUUID: b.DestinationUUID, ServerUUID: b.ServerUUID, ServerID: b.ServerID, Repository: q.Artifact.Repository, Digest: q.Artifact.Digest, Check: func() error { return check(ctx) }}, value)
	out.ReceiptDigest = servicecatalog.Digest(receipt)
	out.ProviderReceiptID = receipt.DeploymentUUID
	out.ProviderStage = receipt.Stage
	if err != nil {
		return out, err
	}
	runtimeTarget := serviceruntime.Target{HostID: target.HostID, HostIdentityDigest: target.HostIdentityDigest, Address: target.Address, User: target.User, HostKey: target.HostKey, Port: target.Port, ExpectedMachineIDDigest: target.ExpectedMachineIDDigest}
	selection := serviceruntime.Selection{Environment: environmentProof, ApplicationUUID: cb.ApplicationUUID, Repository: q.Artifact.Repository, Digest: q.Artifact.Digest}
	if q.Configuration != nil {
		selection.CPUQuotaPercent = q.Configuration.CPUQuotaPercent
		selection.MemoryBytes = q.Configuration.MemoryBytes
	}
	for {
		if err = check(ctx); err != nil {
			return out, err
		}
		receipt, err = client.ObserveDeployment(ctx, cb.ApplicationUUID, receipt.DeploymentUUID, value)
		out.ReceiptDigest = servicecatalog.Digest(receipt)
		if err != nil {
			return out, err
		}
		if err = check(ctx); err != nil {
			return out, err
		}
		if receipt.ProviderStatus == "failed" || receipt.ProviderStatus == "cancelled-by-user" {
			return out, serviceFailure(generated.ErrorCodeDependencyUnavailable)
		}
		snapshot, observeErr := c.runtime.Observe(ctx, runtimeTarget, selection, runtimeValue, check)
		if observeErr == nil {
			out.RuntimeDigest = servicecatalog.Digest(snapshot)
			out.Running = snapshot.Running
			out.Healthy = snapshot.Health == "healthy"
			if snapshot.RepoDigest == q.Artifact.Repository+"@"+q.Artifact.Digest {
				out.RunningDigest = q.Artifact.Digest
			} else {
				out.RunningDigest = "unknown"
			}
			if receipt.ProviderStatus == "finished" && out.Running && out.Healthy && out.RunningDigest == q.Artifact.Digest {
				if err = check(ctx); err != nil {
					return out, err
				}
				if settings != nil {
					if err = client.VerifyImageSettings(ctx, cb.ApplicationUUID, *settings, value, func() error { return check(ctx) }); err != nil {
						return out, err
					}
				}
				out.Status = "succeeded"
				return out, nil
			}
		}
		select {
		case <-ctx.Done():
			return out, serviceFailure(generated.ErrorCodeDependencyUnavailable)
		case <-time.After(time.Second):
		}
	}
}
