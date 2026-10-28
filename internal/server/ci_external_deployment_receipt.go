package server

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/adapter/coolify"
	"github.com/vegastack/vegastack-labs/internal/adapter/serviceruntime"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/servicecatalog"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type ciExternalReceiptContext struct {
	parent adapter.ExactExecutionBinding
	child  generated.Plan
	lease  generated.ExecutorLease
}
type ciExternalReceiptKey struct{}

func withCIExternalDeploymentReceipt(ctx context.Context, parent adapter.ExactExecutionBinding, child generated.Plan, lease generated.ExecutorLease) context.Context {
	return context.WithValue(ctx, ciExternalReceiptKey{}, ciExternalReceiptContext{parent, child, lease})
}

type ciExternalDeploymentReceipt struct {
	deployment *serviceDeploymentComposition
	jobs       *store.CIJobRepository
}

func newCIExternalDeploymentReceipt(deployment *serviceDeploymentComposition, jobs *store.CIJobRepository) adapter.Adapter {
	return &ciExternalDeploymentReceipt{deployment, jobs}
}
func (*ciExternalDeploymentReceipt) Execute(context.Context, adapter.Operation) (adapter.Effect, error) {
	return adapter.Effect{}, serviceFailure(generated.ErrorCodeAuthorizationDenied)
}
func (*ciExternalDeploymentReceipt) Verify(context.Context, adapter.Operation, adapter.Effect) (adapter.Verification, error) {
	return adapter.Verification{}, serviceFailure(generated.ErrorCodeAuthorizationDenied)
}

// Receipt claims are attribution only. Target state is read independently with
// the original durable human/device identity and the still-current exact leases.
func (v *ciExternalDeploymentReceipt) VerifyReceipt(ctx context.Context, op adapter.Operation, claim adapter.ReceiptObservation) (adapter.ReceiptVerification, error) {
	deny := func() (adapter.ReceiptVerification, error) {
		return adapter.ReceiptVerification{}, serviceFailure(generated.ErrorCodeAuthorizationDenied)
	}
	tuple, ok := ctx.Value(ciExternalReceiptKey{}).(ciExternalReceiptContext)
	if !ok || v == nil || v.jobs == nil || v.deployment == nil || v.deployment.base == nil || v.deployment.runtime == nil || adapter.ValidateOperation(op) != nil || adapter.ValidateReceiptObservation(claim) != nil || claim.Status != "succeeded" || op.AdapterID != store.CIExternalDeploymentAdapter || op.OperationType != store.CIExternalDeploymentOperation || op.OperationID != store.CIExternalDeploymentOperationID {
		return deny()
	}
	bound, err := v.jobs.ExecutionReadContext(ctx, tuple.parent.RunID)
	if err != nil {
		return adapter.ReceiptVerification{}, err
	}
	current := func(ctx context.Context) error {
		run, e := store.NewRunRepository(v.deployment.base.store).GetRun(ctx, tuple.lease.RunID)
		if e != nil {
			return e
		}
		if run.RunID != tuple.lease.RunID || len(run.Steps) != 1 || run.Steps[0].StepID != tuple.lease.StepID || tuple.child.PlanID != tuple.lease.PlanID || tuple.child.PlanDigest != tuple.lease.PlanDigest {
			return serviceFailure(generated.ErrorCodePlanStale)
		}
		lease, e := store.NewExecutorLeaseRepository(v.deployment.base.store).Get(ctx, tuple.lease.LeaseID)
		if e != nil {
			return e
		}
		if servicecatalog.Digest(lease) != servicecatalog.Digest(tuple.lease) || lease.Status != "active" {
			return serviceFailure(generated.ErrorCodePlanStale)
		}
		step := run.Steps[0]
		if step.OperationID != op.OperationID || step.OperationType != op.OperationType || step.AdapterID != op.AdapterID || step.ExecutorID != op.ExecutorID || step.TargetID != op.TargetID || step.InputDigest != op.InputDigest || step.ArtifactDigest != op.ArtifactDigest {
			return serviceFailure(generated.ErrorCodePlanStale)
		}
		_, e = v.jobs.ManagedDeploymentReceiptAdmission(ctx, tuple.parent, tuple.child, step, claim)
		return e
	}
	if err = current(bound); err != nil {
		return adapter.ReceiptVerification{}, err
	}
	parent, err := store.NewPlanRepository(v.deployment.base.store).GetPlan(bound, tuple.parent.PlanID)
	if err != nil || parent.Plan.CIJob == nil {
		return deny()
	}
	policy, err := v.jobs.ExternalDeploymentPolicy(parent.Plan.CIJob.ExecutionBindingID)
	if err != nil {
		return adapter.ReceiptVerification{}, err
	}
	if policy.Binding.BindingID == "" || policy.Definition.ServiceID != op.TargetID || policy.Artifact.Digest != op.ArtifactDigest {
		return deny()
	}
	// Guard every provider request, including pagination and intermediate reads.
	source := *v.deployment
	base := *source.base
	source.base = &base
	source.runtime = ciReceiptRuntime{next: source.runtime, check: current}
	base.coolifyTransport = ciReceiptTransport{base.coolifyTransport, current}
	base.harborTransport = ciReceiptTransport{base.harborTransport, current}
	q, err := source.Prepare(bound, generated.ServiceDeploymentDraftRequest{Schema: generated.SchemaIDServiceDeploymentDraftRequest, SchemaVersion: "1.0.0", ServiceID: policy.Definition.ServiceID, ArtifactID: policy.Artifact.ArtifactID, Action: "deploy", ExpectedStateRevision: tuple.child.Binding.StateRevision, RecoveryEpoch: tuple.child.Binding.RecoveryEpoch, IdempotencyKey: "ci-external-receipt", ReasonDigest: tuple.child.Binding.ReasonDigest})
	if err != nil {
		return adapter.ReceiptVerification{}, err
	}
	if q.Definition != policy.Definition || q.Artifact != policy.Artifact || q.Configuration == nil || q.Binding.ConfigurationDigest != policy.ConfigurationDigest {
		return deny()
	}
	target, err := source.authority(bound, q, nil)
	if err != nil {
		return adapter.ReceiptVerification{}, err
	}
	b, err := source.binding(q)
	if err != nil {
		return adapter.ReceiptVerification{}, err
	}
	service, err := base.binding(q.Definition)
	if err != nil || service.Coolify == nil || service.Harbor == nil {
		return deny()
	}
	h := *service.Harbor
	h.ArtifactDigest = q.Artifact.Digest
	image, _, err := base.artifact(bound, q.Definition, false, q.RecoveryEpoch, h)
	if err != nil {
		return adapter.ReceiptVerification{}, err
	}
	if image.Kind != "image" || image.Digest != q.Artifact.Digest {
		return deny()
	}
	hosting, _, err := base.hosting(bound, q.Definition, false, q.RecoveryEpoch, *service.Coolify)
	if err != nil {
		return adapter.ReceiptVerification{}, err
	}
	if hosting.ConfiguredImageName != q.Artifact.Repository || hosting.ConfiguredImageTag != "sha256-"+strings.TrimPrefix(q.Artifact.Digest, "sha256:") {
		return deny()
	}
	value, identity, err := base.borrow(bound, q.Definition, false, q.RecoveryEpoch, b.RuntimeReferenceID, "service.runtime", "runtime-observe", "credential.service-runtime.read")
	if err != nil {
		return adapter.ReceiptVerification{}, err
	}
	defer value.Close()
	environmentIdentities := make([]serviceCredentialIdentity, 0, len(b.EnvironmentSecrets))
	check := func(ctx context.Context) error {
		if e := current(ctx); e != nil {
			return e
		}
		if _, e := source.authority(ctx, q, &target); e != nil {
			return e
		}
		for i, id := range environmentIdentities {
			secret := b.EnvironmentSecrets[i]
			if e := base.recheckCredential(ctx, q.Definition, false, q.RecoveryEpoch, secret.ReferenceID, "service.environment", "workload-env", "credential.service-environment.read", id); e != nil {
				return e
			}
		}
		return base.recheckCredential(ctx, q.Definition, false, q.RecoveryEpoch, b.RuntimeReferenceID, "service.runtime", "runtime-observe", "credential.service-runtime.read", identity)
	}
	environment := make([]serviceruntime.EnvironmentFingerprint, 0, len(b.EnvironmentSecrets))
	for _, secret := range b.EnvironmentSecrets {
		secretValue, id, e := base.borrow(bound, q.Definition, false, q.RecoveryEpoch, secret.ReferenceID, "service.environment", "workload-env", "credential.service-environment.read")
		if e != nil {
			return adapter.ReceiptVerification{}, e
		}
		if id.Fingerprint != secret.ExpectedFingerprint {
			secretValue.Close()
			return deny()
		}
		environmentIdentities = append(environmentIdentities, id)
		environment = append(environment, serviceruntime.EnvironmentFingerprint{Name: secret.Name, Digest: serviceruntime.EnvironmentDigest(secret.Name, secretValue.Bytes())})
		secretValue.Close()
	}
	cb := service.Coolify
	readValue, readIdentity, err := base.borrow(bound, q.Definition, false, q.RecoveryEpoch, cb.ObservationReferenceID, "hosting.coolify", "hosting-observe", "credential.hosting.read")
	if err != nil {
		return adapter.ReceiptVerification{}, err
	}
	defer readValue.Close()
	settings, err := coolify.Settings(*q.Configuration)
	if err != nil {
		return adapter.ReceiptVerification{}, err
	}
	client, err := coolify.NewClient(cb.Origin, base.coolifyTransport)
	if err != nil {
		return adapter.ReceiptVerification{}, err
	}
	if err = client.VerifyImageSettings(bound, cb.ApplicationUUID, settings, readValue, func() error { return check(bound) }); err != nil {
		return adapter.ReceiptVerification{}, err
	}
	if err = base.recheckCredential(bound, q.Definition, false, q.RecoveryEpoch, cb.ObservationReferenceID, "hosting.coolify", "hosting-observe", "credential.hosting.read", readIdentity); err != nil {
		return adapter.ReceiptVerification{}, err
	}
	if err = check(bound); err != nil {
		return adapter.ReceiptVerification{}, err
	}
	snapshot, err := source.runtime.Observe(bound, serviceruntime.Target{HostID: target.HostID, HostIdentityDigest: target.HostIdentityDigest, Address: target.Address, User: target.User, HostKey: target.HostKey, Port: target.Port, ExpectedMachineIDDigest: target.ExpectedMachineIDDigest}, serviceruntime.Selection{ApplicationUUID: cb.ApplicationUUID, Repository: q.Artifact.Repository, Digest: q.Artifact.Digest, CPUQuotaPercent: q.Configuration.CPUQuotaPercent, MemoryBytes: q.Configuration.MemoryBytes, Environment: environment}, value, check)
	if err != nil {
		return adapter.ReceiptVerification{}, err
	}
	if err = check(bound); err != nil {
		return adapter.ReceiptVerification{}, err
	}
	if !ciExternalRuntimeMatches(snapshot, q.Artifact) {
		return deny()
	}
	digest := servicecatalog.Digest(struct {
		Policy, Claim string
		Hosting       any
		Runtime       serviceruntime.Snapshot
	}{policy.Digest(), claim.ResultDigest, hosting, snapshot})
	return adapter.ReceiptVerification{Verified: true, Digest: digest, Changed: true}, nil
}
func ciExternalRuntimeMatches(s serviceruntime.Snapshot, a generated.ServiceDeploymentArtifact) bool {
	return s.Running && s.Health == "healthy" && s.RepoDigest == a.Repository+"@"+a.Digest
}

type ciReceiptTransport struct {
	next  http.RoundTripper
	check func(context.Context) error
}

func (t ciReceiptTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if e := t.check(r.Context()); e != nil {
		return nil, e
	}
	next := t.next
	if next == nil {
		next = &http.Transport{Proxy: nil, ForceAttemptHTTP2: true, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second, DisableKeepAlives: true}
	}
	response, err := next.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	if e := t.check(r.Context()); e != nil {
		response.Body.Close()
		return nil, e
	}
	return response, nil
}

// Wrap existing read-only runtime observers so every SSH command retains the
// receipt-stage controller authority as well as the service observer checks.
type ciReceiptRuntime struct {
	next  serviceruntime.Observer
	check func(context.Context) error
}

func (r ciReceiptRuntime) combined(check serviceruntime.Check) serviceruntime.Check {
	return func(ctx context.Context) error {
		if e := r.check(ctx); e != nil {
			return e
		}
		return check(ctx)
	}
}
func (r ciReceiptRuntime) Observe(ctx context.Context, t serviceruntime.Target, s serviceruntime.Selection, v *credentialref.Value, check serviceruntime.Check) (serviceruntime.Snapshot, error) {
	combined := r.combined(check)
	if e := combined(ctx); e != nil {
		return serviceruntime.Snapshot{}, e
	}
	out, e := r.next.Observe(ctx, t, s, v, combined)
	if e != nil {
		return serviceruntime.Snapshot{}, e
	}
	if e = combined(ctx); e != nil {
		return serviceruntime.Snapshot{}, e
	}
	return out, nil
}
func (r ciReceiptRuntime) ObserveCapacity(ctx context.Context, t serviceruntime.Target, v *credentialref.Value, check serviceruntime.Check) (serviceruntime.CapacitySnapshot, error) {
	observer, ok := r.next.(serviceruntime.CapacityObserver)
	if !ok {
		return serviceruntime.CapacitySnapshot{}, serviceFailure(generated.ErrorCodePrerequisiteBlocked)
	}
	combined := r.combined(check)
	if e := combined(ctx); e != nil {
		return serviceruntime.CapacitySnapshot{}, e
	}
	out, e := observer.ObserveCapacity(ctx, t, v, combined)
	if e != nil {
		return serviceruntime.CapacitySnapshot{}, e
	}
	if e = combined(ctx); e != nil {
		return serviceruntime.CapacitySnapshot{}, e
	}
	return out, nil
}
