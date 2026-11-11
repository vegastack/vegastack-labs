package server

import (
	"context"
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter/coolify"
	"github.com/vegastack/vegastack-labs/internal/adapter/serviceruntime"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/servicecatalog"
)

// reconcileDeployment adopts one explicitly approved receipt after independent
// current observation. It never borrows the provider mutation credential and
// never invokes deployment, configuration, environment or rollback writes.
func (c *serviceDeploymentComposition) reconcileDeployment(ctx context.Context, q generated.ServiceDeploymentRequest, actor identity.Principal) (out servicecatalog.DeploymentOutcome, err error) {
	out.Status = "partial"
	if !identity.ValidPrincipal(actor) {
		return out, serviceFailure(generated.ErrorCodeAuthenticationRequired)
	}
	ctx = identity.WithVerifiedPrincipal(ctx, actor)
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	attempt, err := c.repo.RecoveryAttempt(ctx, q)
	if err != nil {
		return out, err
	}
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
	h := *service.Harbor
	h.ArtifactDigest = q.Artifact.Digest
	artifact, _, err := c.base.artifact(ctx, q.Definition, false, q.RecoveryEpoch, h)
	if err != nil {
		return out, err
	}
	if artifact.Kind != "image" || artifact.Digest != q.Artifact.Digest {
		return out, serviceFailure(generated.ErrorCodeEvidenceInvalid)
	}
	cb := service.Coolify
	value, credential, err := c.base.borrow(ctx, q.Definition, false, q.RecoveryEpoch, cb.ObservationReferenceID, "hosting.coolify", "hosting-observe", "credential.hosting.read")
	if err != nil {
		return out, err
	}
	defer value.Close()
	runtimeValue, runtimeCredential, err := c.base.borrow(ctx, q.Definition, false, q.RecoveryEpoch, b.RuntimeReferenceID, "service.runtime", "runtime-observe", "credential.service-runtime.read")
	if err != nil {
		return out, err
	}
	defer runtimeValue.Close()
	// Environment is fingerprinted for native observation only, never sent to the provider.
	var envValues []*credentialref.Value
	defer func() {
		for _, v := range envValues {
			v.Close()
		}
	}()
	var envIdentities []serviceCredentialIdentity
	var environment []serviceruntime.EnvironmentFingerprint
	for _, s := range b.EnvironmentSecrets {
		v, id, e := c.base.borrow(ctx, q.Definition, false, q.RecoveryEpoch, s.ReferenceID, "service.environment", "workload-env", "credential.service-environment.read")
		if e != nil {
			return out, e
		}
		envValues = append(envValues, v)
		if id.Fingerprint != s.ExpectedFingerprint {
			return out, serviceFailure(generated.ErrorCodePlanStale)
		}
		envIdentities = append(envIdentities, id)
		environment = append(environment, serviceruntime.EnvironmentFingerprint{Name: s.Name, Digest: serviceruntime.EnvironmentDigest(s.Name, v.Bytes())})
	}
	shared, err := c.sharedCPUAdmission(ctx, q.Definition, b, q.RecoveryEpoch)
	if err != nil {
		return out, err
	}
	check := func(ctx context.Context) error {
		if e := c.repo.Authorize(ctx, q); e != nil {
			return e
		}
		if _, e := c.authority(ctx, q, &target); e != nil {
			return e
		}
		current, e := c.sharedCPUAdmission(ctx, q.Definition, b, q.RecoveryEpoch)
		if e != nil {
			return e
		}
		if current != shared {
			return serviceFailure(generated.ErrorCodePlanStale)
		}
		fresh, e := c.repo.RecoveryAttempt(ctx, q)
		if e != nil {
			return e
		}
		if fresh.PlanDigest != attempt.PlanDigest || !fresh.StartedAt.Equal(attempt.StartedAt) || !fresh.FinishedAt.Equal(attempt.FinishedAt) {
			return serviceFailure(generated.ErrorCodePlanStale)
		}
		if e = c.base.recheckCredential(ctx, q.Definition, false, q.RecoveryEpoch, cb.ObservationReferenceID, "hosting.coolify", "hosting-observe", "credential.hosting.read", credential); e != nil {
			return e
		}
		for i, s := range b.EnvironmentSecrets {
			if e = c.base.recheckCredential(ctx, q.Definition, false, q.RecoveryEpoch, s.ReferenceID, "service.environment", "workload-env", "credential.service-environment.read", envIdentities[i]); e != nil {
				return e
			}
		}
		return c.base.recheckCredential(ctx, q.Definition, false, q.RecoveryEpoch, b.RuntimeReferenceID, "service.runtime", "runtime-observe", "credential.service-runtime.read", runtimeCredential)
	}
	if err = check(ctx); err != nil {
		return out, err
	}
	actual, err := c.observeCapacity(ctx, q.Definition, b)
	if err != nil {
		return out, err
	}
	if err = c.repo.CheckPlacement(ctx, q.Definition, *q.Configuration, actual); err != nil {
		return out, err
	}
	client, err := coolify.NewClient(cb.Origin, c.base.coolifyTransport)
	if err != nil {
		return out, err
	}
	app := coolify.ApplicationTarget{TeamID: cb.TeamID, ProjectID: cb.ProjectID, EnvironmentID: cb.EnvironmentID, DestinationID: cb.DestinationID, ProjectUUID: cb.ProjectUUID, Environment: cb.Environment, ApplicationUUID: cb.ApplicationUUID, DestinationType: cb.DestinationType}
	receipt, err := client.ObserveBoundDeployment(ctx, app, b.ServerID, q.Recovery.ProviderReceiptID, value, func() error { return check(ctx) })
	out.ProviderReceiptID = receipt.DeploymentUUID
	out.ProviderStage = receipt.Stage
	out.ReceiptDigest = servicecatalog.Digest(receipt)
	if err != nil {
		return out, err
	}
	created, e := time.Parse(time.RFC3339Nano, receipt.CreatedAt)
	if e != nil || created.Before(attempt.StartedAt) || created.After(attempt.FinishedAt) {
		return out, serviceFailure(generated.ErrorCodeIntegrityFailure)
	}
	snapshot, e := client.ObserveApplication(ctx, app, value)
	if e != nil {
		return out, e
	}
	if snapshot.ConfiguredImageName != q.Artifact.Repository || snapshot.ConfiguredImageTag != "sha256-"+strings.TrimPrefix(q.Artifact.Digest, "sha256:") {
		return out, serviceFailure(generated.ErrorCodeIntegrityFailure)
	}
	manual, e := c.manualAdmission(ctx, q.Definition, b, q.RecoveryEpoch)
	if e != nil {
		return out, e
	}
	settings, e := deploymentImageSettings(*q.Configuration, manual)
	if e != nil {
		return out, e
	}
	if err = client.VerifyImageSettings(ctx, cb.ApplicationUUID, settings, value, func() error { return check(ctx) }); err != nil {
		return out, err
	}
	rt := serviceruntime.Target{HostID: target.HostID, HostIdentityDigest: target.HostIdentityDigest, Address: target.Address, User: target.User, HostKey: target.HostKey, Port: target.Port, ExpectedMachineIDDigest: target.ExpectedMachineIDDigest}
	native, e := c.runtime.Observe(ctx, rt, serviceruntime.Selection{Environment: environment, ApplicationUUID: cb.ApplicationUUID, Repository: q.Artifact.Repository, Digest: q.Artifact.Digest, CPUQuotaPercent: q.Configuration.CPUQuotaPercent, MemoryBytes: q.Configuration.MemoryBytes}, runtimeValue, check)
	if e != nil {
		return out, e
	}
	out.RuntimeDigest = servicecatalog.Digest(native)
	out.Running = native.Running
	out.Healthy = native.Health == "healthy"
	if native.RepoDigest == q.Artifact.Repository+"@"+q.Artifact.Digest {
		out.RunningDigest = q.Artifact.Digest
	}
	if !out.Running || !out.Healthy || out.RunningDigest != q.Artifact.Digest {
		return out, serviceFailure(generated.ErrorCodeEvidenceInvalid)
	}
	if err = check(ctx); err != nil {
		return out, err
	}
	out.Status = "succeeded"
	return out, nil
}
