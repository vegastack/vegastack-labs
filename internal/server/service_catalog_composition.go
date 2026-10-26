package server

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/adapter/coolify"
	"github.com/vegastack/vegastack-labs/internal/adapter/harbor"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/servicecatalog"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type serviceCatalogComposition struct {
	repo     *store.ServiceRepository
	creds    *store.CredentialRepository
	gates    *store.GateRepository
	store    *store.Store
	registry *adapter.Registry
	bindings map[string]generated.ServiceProviderBinding
	// Only trusted server fixtures can replace transports. Neither public input
	// nor the protected profile carries a transport or arbitrary request path.
	coolifyTransport, harborTransport http.RoundTripper
}

type serviceCredentialIdentity struct {
	ReferenceID, ConsumerID, PurposeID, TargetID, ResolverID, MaterialVersion, Fingerprint, ProfileDigest string
	ReferenceStateRevision, RecoveryEpoch                                                                 int64
}
type serviceProviderSnapshot struct {
	Hosting     coolify.ApplicationSnapshot
	Artifact    *harbor.ArtifactSnapshot
	Credentials []serviceCredentialIdentity
}

// An unavailable provider or credential is displayable; current authorization,
// protected binding and epoch failures remain fatal and cannot become status.
type serviceReadUnavailable struct {
	credential bool
	cause      error
}

func (e *serviceReadUnavailable) Error() string { return "service provider observation unavailable" }
func (e *serviceReadUnavailable) Unwrap() error { return e.cause }
func serviceUnavailable(err error, credential bool) error {
	if err == nil {
		return nil
	}
	return &serviceReadUnavailable{credential: credential, cause: err}
}
func serviceDisplayable(err error) bool {
	var unavailable *serviceReadUnavailable
	return err == nil || errors.As(err, &unavailable)
}

func serviceFailure(code string) error { return failure.New(code, "service-observation", false) }
func servicePolicies(bindings []generated.ServiceProviderBinding) ([]servicecatalog.Policy, error) {
	frozen, err := serverconfig.FreezeServiceBindings(bindings)
	if err != nil {
		return nil, err
	}
	policies := make([]servicecatalog.Policy, 0, len(frozen))
	for _, binding := range frozen {
		policies = append(policies, servicecatalog.Policy{Definition: serviceBindingDefinition(binding), ResourceKeyDigest: servicecatalog.Digest([]string{binding.Coolify.Origin, binding.Coolify.ApplicationUUID})})
	}
	return policies, nil
}
func serviceBindingDefinition(binding generated.ServiceProviderBinding) generated.ServiceDefinition {
	return generated.ServiceDefinition{Schema: generated.SchemaIDServiceDefinition, SchemaVersion: "1.0.0", ServiceID: binding.ServiceID, EnvironmentID: binding.EnvironmentID, OwnerID: binding.OwnerID, HostID: binding.HostID, HostIdentityDigest: binding.HostIdentityDigest, BindingID: binding.BindingID, BindingDigest: servicecatalog.Digest(binding)}
}
func newServiceCatalogComposition(ctx context.Context, p serverconfig.Profile, s *store.Store, registry *adapter.Registry, dbpath string) (*serviceCatalogComposition, error) {
	if s == nil || registry == nil {
		return nil, serviceFailure(generated.ErrorCodeInputInvalid)
	}
	frozen, err := serverconfig.FreezeServiceBindings(p.ServiceBindings)
	if err != nil {
		return nil, err
	}
	c := &serviceCatalogComposition{repo: store.NewServiceRepository(s), creds: store.NewCredentialRepository(s), gates: store.NewGateRepository(s), store: s, registry: registry, bindings: make(map[string]generated.ServiceProviderBinding, len(frozen))}
	for _, binding := range frozen {
		c.bindings[binding.BindingID] = binding
	}
	if len(frozen) > 0 {
		if err := composeServiceCatalogNative(ctx, p, dbpath, s, registry); err != nil {
			return nil, err
		}
	}
	return c, nil
}
func (c *serviceCatalogComposition) binding(def generated.ServiceDefinition) (generated.ServiceProviderBinding, error) {
	binding, ok := c.bindings[def.BindingID]
	if !ok || servicecatalog.Digest(serviceBindingDefinition(binding)) != servicecatalog.Digest(def) {
		return generated.ServiceProviderBinding{}, serviceFailure(generated.ErrorCodePlanStale)
	}
	return binding, nil
}
func (c *serviceCatalogComposition) check(ctx context.Context, def generated.ServiceDefinition, importing bool, epoch int64) (store.RevisionToken, error) {
	if _, err := c.binding(def); err != nil {
		return store.RevisionToken{}, err
	}
	if importing {
		if err := c.repo.AuthorizeImport(ctx, def); err != nil {
			return store.RevisionToken{}, err
		}
	} else {
		record, err := c.repo.Get(ctx, def.ServiceID)
		if err != nil {
			return store.RevisionToken{}, err
		}
		if servicecatalog.Digest(record.Definition) != servicecatalog.Digest(def) {
			return store.RevisionToken{}, serviceFailure(generated.ErrorCodePlanStale)
		}
	}
	health, err := c.store.Health(ctx)
	if err != nil {
		return store.RevisionToken{}, err
	}
	if health.Revision.RecoveryEpoch != epoch {
		return store.RevisionToken{}, serviceFailure(generated.ErrorCodeRecoveryEpochMismatch)
	}
	return health.Revision, nil
}
func serviceProfileDigest(scope store.GateAppliedProfile) string {
	scope.StateRevision = 0
	scope.Capabilities = slices.Clone(scope.Capabilities)
	slices.Sort(scope.Capabilities)
	return servicecatalog.Digest(scope)
}
func (c *serviceCatalogComposition) credential(ctx context.Context, def generated.ServiceDefinition, importing bool, epoch int64, reference, consumer, purpose, capability string) (credentialref.StepBinding, serviceCredentialIdentity, error) {
	revision, err := c.check(ctx, def, importing, epoch)
	if err != nil {
		return credentialref.StepBinding{}, serviceCredentialIdentity{}, err
	}
	scope, err := c.gates.GetAppliedProfileScope(ctx)
	if err != nil || scope.RecoveryEpoch != epoch || scope.StateRevision > revision.StateRevision || !slices.Contains(scope.Capabilities, capability) {
		return credentialref.StepBinding{}, serviceCredentialIdentity{}, serviceUnavailable(serviceFailure(generated.ErrorCodePrerequisiteBlocked), true)
	}
	ref, err := c.creds.GetReference(ctx, reference)
	if err != nil || ref.ReferenceID != reference || ref.Status != "active" || ref.ActivatedAt == nil || ref.MaterialVersion == "" || ref.ConsumerID != consumer || ref.PurposeID != purpose || ref.TargetID != def.ServiceID || ref.RecoveryEpoch != epoch || ref.StateRevision > revision.StateRevision || !slices.Contains(ref.VerifiedConsumerIDs, consumer) {
		return credentialref.StepBinding{}, serviceCredentialIdentity{}, serviceUnavailable(serviceFailure(generated.ErrorCodePrerequisiteBlocked), true)
	}
	cap, err := c.registry.ResolveCredentialCapability(ref.ResolverID, consumer, scope.ProfileID)
	if err != nil || cap != capability || !slices.Contains(scope.Capabilities, cap) {
		return credentialref.StepBinding{}, serviceCredentialIdentity{}, serviceUnavailable(serviceFailure(generated.ErrorCodePrerequisiteBlocked), true)
	}
	operationID := servicecatalog.OperationID
	if consumer == "hosting.coolify.deploy" || consumer == "service.runtime" || consumer == "service.environment" {
		operationID = servicecatalog.DeploymentOperationID
	}
	if consumer == "service.recovery" || consumer == "service.recovery.repository" {
		operationID = "service-recovery"
	}
	binding := credentialref.StepBinding{OperationID: operationID, AdapterID: consumer, ConsumerID: consumer, PurposeID: purpose, TargetID: def.ServiceID, ReferenceID: reference, ResolverID: ref.ResolverID, MaterialVersion: ref.MaterialVersion, StateRevision: revision.StateRevision, RecoveryEpoch: epoch}
	if !credentialref.ValidBinding(binding) {
		return credentialref.StepBinding{}, serviceCredentialIdentity{}, serviceUnavailable(serviceFailure(generated.ErrorCodePrerequisiteBlocked), true)
	}
	identity := serviceCredentialIdentity{ReferenceID: reference, ConsumerID: consumer, PurposeID: purpose, TargetID: def.ServiceID, ResolverID: ref.ResolverID, MaterialVersion: ref.MaterialVersion, Fingerprint: ref.Fingerprint, ProfileDigest: serviceProfileDigest(scope), ReferenceStateRevision: ref.StateRevision, RecoveryEpoch: epoch}
	return binding, identity, nil
}
func (c *serviceCatalogComposition) borrow(ctx context.Context, def generated.ServiceDefinition, importing bool, epoch int64, reference, consumer, purpose, capability string) (*credentialref.Value, serviceCredentialIdentity, error) {
	binding, initial, err := c.credential(ctx, def, importing, epoch, reference, consumer, purpose, capability)
	if err != nil {
		return nil, initial, err
	}
	scope, err := c.gates.GetAppliedProfileScope(ctx)
	if err != nil || serviceProfileDigest(scope) != initial.ProfileDigest {
		return nil, initial, serviceFailure(generated.ErrorCodePlanStale)
	}
	resolver, err := c.registry.ResolveCredentialResolver(binding.ResolverID, consumer, scope.ProfileID)
	if err != nil {
		return nil, initial, serviceUnavailable(err, true)
	}
	value, err := resolver.Resolve(ctx, binding)
	if err != nil {
		if value != nil {
			value.Close()
		}
		if currentErr := c.recheckCredential(ctx, def, importing, epoch, reference, consumer, purpose, capability, initial); currentErr != nil {
			return nil, initial, currentErr
		}
		return nil, initial, serviceUnavailable(err, true)
	}
	if value == nil || len(value.Bytes()) == 0 {
		if value != nil {
			value.Close()
		}
		if currentErr := c.recheckCredential(ctx, def, importing, epoch, reference, consumer, purpose, capability, initial); currentErr != nil {
			return nil, initial, currentErr
		}
		return nil, initial, serviceUnavailable(serviceFailure(generated.ErrorCodePrerequisiteBlocked), true)
	}
	if err := c.recheckCredential(ctx, def, importing, epoch, reference, consumer, purpose, capability, initial); err != nil {
		value.Close()
		return nil, initial, err
	}
	return value, initial, nil
}
func (c *serviceCatalogComposition) recheckCredential(ctx context.Context, def generated.ServiceDefinition, importing bool, epoch int64, reference, consumer, purpose, capability string, initial serviceCredentialIdentity) error {
	_, current, err := c.credential(ctx, def, importing, epoch, reference, consumer, purpose, capability)
	if err != nil {
		if serviceDisplayable(err) {
			return serviceFailure(generated.ErrorCodePlanStale)
		}
		return err
	}
	if current != initial {
		return serviceFailure(generated.ErrorCodePlanStale)
	}
	return nil
}
func (c *serviceCatalogComposition) hosting(ctx context.Context, def generated.ServiceDefinition, importing bool, epoch int64, b generated.CoolifyServiceBinding) (coolify.ApplicationSnapshot, serviceCredentialIdentity, error) {
	const consumer, purpose, capability = "hosting.coolify", "hosting-observe", "credential.hosting.read"
	value, credential, err := c.borrow(ctx, def, importing, epoch, b.ObservationReferenceID, consumer, purpose, capability)
	if err != nil {
		return coolify.ApplicationSnapshot{}, credential, err
	}
	client, err := coolify.NewClient(b.Origin, c.coolifyTransport)
	var snapshot coolify.ApplicationSnapshot
	if err == nil {
		snapshot, err = client.ObserveApplication(ctx, coolify.ApplicationTarget{TeamID: b.TeamID, ProjectID: b.ProjectID, EnvironmentID: b.EnvironmentID, DestinationID: b.DestinationID, ProjectUUID: b.ProjectUUID, Environment: b.Environment, ApplicationUUID: b.ApplicationUUID, DestinationType: b.DestinationType}, value)
	}
	value.Close()
	if currentErr := c.recheckCredential(ctx, def, importing, epoch, b.ObservationReferenceID, consumer, purpose, capability, credential); currentErr != nil {
		return coolify.ApplicationSnapshot{}, credential, currentErr
	}
	return snapshot, credential, serviceUnavailable(err, false)
}
func (c *serviceCatalogComposition) artifact(ctx context.Context, def generated.ServiceDefinition, importing bool, epoch int64, b generated.HarborServiceBinding) (harbor.ArtifactSnapshot, serviceCredentialIdentity, error) {
	const consumer, purpose, capability = "registry.harbor", "registry-observe", "credential.registry.read"
	value, credential, err := c.borrow(ctx, def, importing, epoch, b.ObservationReferenceID, consumer, purpose, capability)
	if err != nil {
		return harbor.ArtifactSnapshot{}, credential, err
	}
	client, err := harbor.NewClient(b.Origin, c.harborTransport)
	var snapshot harbor.ArtifactSnapshot
	if err == nil {
		snapshot, err = client.InspectArtifact(ctx, harbor.ArtifactTarget{Project: b.Project, Repository: b.Repository, Digest: b.ArtifactDigest}, b.RobotUsername, value)
	}
	value.Close()
	if currentErr := c.recheckCredential(ctx, def, importing, epoch, b.ObservationReferenceID, consumer, purpose, capability, credential); currentErr != nil {
		return harbor.ArtifactSnapshot{}, credential, currentErr
	}
	return snapshot, credential, serviceUnavailable(err, false)
}
func serviceSnapshotDigest(snapshot serviceProviderSnapshot) string {
	if snapshot.Artifact != nil {
		copy := *snapshot.Artifact
		copy.ObservedAt = time.Time{}
		snapshot.Artifact = &copy
	}
	return servicecatalog.Digest(snapshot)
}
func (c *serviceCatalogComposition) importSnapshot(ctx context.Context, request generated.ServiceImportRequest) (serviceProviderSnapshot, error) {
	def, epoch := request.Definition, request.RecoveryEpoch
	binding, err := c.binding(def)
	if err != nil {
		return serviceProviderSnapshot{}, err
	}
	hosting, credential, err := c.hosting(ctx, def, true, epoch, *binding.Coolify)
	if err != nil {
		return serviceProviderSnapshot{}, err
	}
	snapshot := serviceProviderSnapshot{Hosting: hosting, Credentials: []serviceCredentialIdentity{credential}}
	if binding.Harbor != nil {
		artifact, credential, err := c.artifact(ctx, def, true, epoch, *binding.Harbor)
		if err != nil {
			return serviceProviderSnapshot{}, err
		}
		snapshot.Artifact = &artifact
		snapshot.Credentials = append(snapshot.Credentials, credential)
	}
	for _, initial := range snapshot.Credentials {
		capability := "credential.hosting.read"
		if initial.ConsumerID == "registry.harbor" {
			capability = "credential.registry.read"
		}
		if err := c.recheckCredential(ctx, def, true, epoch, initial.ReferenceID, initial.ConsumerID, initial.PurposeID, capability, initial); err != nil {
			return serviceProviderSnapshot{}, err
		}
	}
	if _, err := c.check(ctx, def, true, epoch); err != nil {
		return serviceProviderSnapshot{}, err
	}
	return snapshot, nil
}
func (c *serviceCatalogComposition) Prepare(ctx context.Context, draft generated.ServiceImportDraftRequest) (generated.ServiceImportRequest, error) {
	request, err := c.repo.Prepare(ctx, draft)
	if err != nil {
		return generated.ServiceImportRequest{}, err
	}
	snapshot, err := c.importSnapshot(ctx, request)
	if err != nil {
		return generated.ServiceImportRequest{}, err
	}
	request.ObservationDigest = serviceSnapshotDigest(snapshot)
	return request, nil
}
func (c *serviceCatalogComposition) VerifyImport(ctx context.Context, request generated.ServiceImportRequest, actor identity.Principal) error {
	if !identity.ValidPrincipal(actor) {
		return serviceFailure(generated.ErrorCodeAuthenticationRequired)
	}
	ctx = identity.WithVerifiedPrincipal(ctx, actor)
	snapshot, err := c.importSnapshot(ctx, request)
	if err != nil {
		return err
	}
	if serviceSnapshotDigest(snapshot) != request.ObservationDigest {
		return serviceFailure(generated.ErrorCodePlanStale)
	}
	return nil
}
func serviceProviderReason(err error) string {
	if err == nil {
		return "observed"
	}
	var unavailable *serviceReadUnavailable
	if errors.As(err, &unavailable) && unavailable.credential {
		return "credential-unavailable"
	}
	return "provider-unavailable"
}
func serviceObservation(def generated.ServiceDefinition, revision store.RevisionToken, hosting coolify.ApplicationSnapshot, hostingErr error, artifact *harbor.ArtifactSnapshot, artifactErr error, artifactConfigured bool) generated.ServiceObservation {
	out := generated.ServiceObservation{Schema: generated.SchemaIDServiceObservation, SchemaVersion: "1.0.0", ServiceID: def.ServiceID, BindingDigest: def.BindingDigest, ObservedAt: time.Now().UTC().Format(time.RFC3339), HostingState: "unavailable", HostingReason: serviceProviderReason(hostingErr), ProviderStatus: "unknown", ArtifactState: "not-configured", ArtifactReason: "not-configured", ArtifactKind: "unknown", ScanState: "unknown", SignatureState: "unverified", ProvenanceState: "unverified", RunningDigestState: "unknown", HealthState: "unknown", HostAdmission: "not-verified", StateRevision: revision.StateRevision, RecoveryEpoch: revision.RecoveryEpoch}
	if hostingErr == nil {
		out.HostingState = "observed"
		out.ProviderStatus = hosting.ProviderStatus
		out.ConfiguredImage = hosting.ConfiguredImageName
		if out.ConfiguredImage != "" && hosting.ConfiguredImageTag != "" {
			out.ConfiguredImage += ":" + hosting.ConfiguredImageTag
		}
	}
	if artifactConfigured {
		out.ArtifactState = "unavailable"
		out.ArtifactReason = serviceProviderReason(artifactErr)
		if artifactErr == nil && artifact != nil {
			out.ArtifactState = "observed"
			out.ArtifactDigest = artifact.Digest
			out.ArtifactKind = artifact.Kind
			out.ScanState = artifact.ScanState
		}
	}
	return out
}
func (c *serviceCatalogComposition) Observe(ctx context.Context, id string) (generated.ServiceObservation, error) {
	record, err := c.repo.Get(ctx, id)
	if err != nil {
		return generated.ServiceObservation{}, err
	}
	binding, err := c.binding(record.Definition)
	if err != nil {
		return generated.ServiceObservation{}, err
	}
	health, err := c.store.Health(ctx)
	if err != nil {
		return generated.ServiceObservation{}, err
	}
	epoch := health.Revision.RecoveryEpoch
	hosting, hostingCredential, hostingErr := c.hosting(ctx, record.Definition, false, epoch, *binding.Coolify)
	if !serviceDisplayable(hostingErr) {
		return generated.ServiceObservation{}, hostingErr
	}
	var artifact *harbor.ArtifactSnapshot
	var artifactErr error
	var artifactCredential serviceCredentialIdentity
	if binding.Harbor != nil {
		snapshot, credential, err := c.artifact(ctx, record.Definition, false, epoch, *binding.Harbor)
		artifactCredential = credential
		artifactErr = err
		if !serviceDisplayable(artifactErr) {
			return generated.ServiceObservation{}, artifactErr
		}
		if err == nil {
			artifact = &snapshot
		}
	}
	if hostingErr == nil {
		hostingErr = c.recheckCredential(ctx, record.Definition, false, epoch, hostingCredential.ReferenceID, "hosting.coolify", "hosting-observe", "credential.hosting.read", hostingCredential)
	}
	if binding.Harbor != nil && artifactErr == nil {
		artifactErr = c.recheckCredential(ctx, record.Definition, false, epoch, artifactCredential.ReferenceID, "registry.harbor", "registry-observe", "credential.registry.read", artifactCredential)
	}
	if !serviceDisplayable(hostingErr) {
		return generated.ServiceObservation{}, hostingErr
	}
	if !serviceDisplayable(artifactErr) {
		return generated.ServiceObservation{}, artifactErr
	}
	current, err := c.repo.Get(ctx, id)
	if err != nil {
		return generated.ServiceObservation{}, err
	}
	if current.Revision != record.Revision || servicecatalog.Digest(current.Definition) != servicecatalog.Digest(record.Definition) {
		return generated.ServiceObservation{}, serviceFailure(generated.ErrorCodePlanStale)
	}
	revision, err := c.check(ctx, current.Definition, false, epoch)
	if err != nil {
		return generated.ServiceObservation{}, err
	}
	return serviceObservation(current.Definition, revision, hosting, hostingErr, artifact, artifactErr, binding.Harbor != nil), nil
}
