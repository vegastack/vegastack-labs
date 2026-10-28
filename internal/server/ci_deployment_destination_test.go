package server

import (
	"context"
	"errors"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/store"
	"testing"
	"time"
)

type ciBrokerSyntheticRecords struct {
	lease     generated.ExecutorLease
	policy    store.CIExternalDeploymentPolicy
	profile   store.GateAppliedProfile
	reference generated.CredentialReference
	consumed  int
}

func (s *ciBrokerSyntheticRecords) Lease(context.Context, string) (generated.ExecutorLease, error) {
	return s.lease, nil
}
func (s *ciBrokerSyntheticRecords) Admission(context.Context, adapter.ExactExecutionBinding, generated.Plan, generated.RunStep) (store.CIManagedDeploymentAdmission, error) {
	return store.CIManagedDeploymentAdmission{ExecutionBinding: generated.CiJobExecutionBinding{BindingID: "execution-one"}}, nil
}
func (s *ciBrokerSyntheticRecords) Policy(string) (store.CIExternalDeploymentPolicy, error) {
	return s.policy, nil
}
func (s *ciBrokerSyntheticRecords) Profile(context.Context) (store.GateAppliedProfile, error) {
	return s.profile, nil
}
func (s *ciBrokerSyntheticRecords) Reference(context.Context, string, int64) (generated.CredentialReference, error) {
	return s.reference, nil
}
func (s *ciBrokerSyntheticRecords) Handoff(context.Context, adapter.ExactExecutionBinding, generated.Plan, generated.ExecutorLease) error {
	s.consumed++
	return nil
}
func (s *ciBrokerSyntheticRecords) ReadContext(ctx context.Context, _ string) (context.Context, error) {
	return ctx, nil
}

type ciBrokerSyntheticDestination struct {
	snapshot  store.HostAdmissionSnapshot
	err       error
	calls     int
	requested string
}

func (d *ciBrokerSyntheticDestination) roleAdmission(_ context.Context, id string) (store.HostAdmissionSnapshot, error) {
	d.calls++
	d.requested = id
	return d.snapshot, d.err
}

type ciBrokerSyntheticResolver struct {
	calls     int
	onResolve func()
	value     *credentialref.Value
}

func (r *ciBrokerSyntheticResolver) Resolve(context.Context, credentialref.StepBinding) (*credentialref.Value, error) {
	r.calls++
	if r.onResolve != nil {
		r.onResolve()
	}
	var e error
	r.value, e = credentialref.NewValue([]byte("synthetic-hosting-credential"))
	return r.value, e
}
func ciBrokerDestinationFixture(t *testing.T) (*ciDeploymentBroker, *ciBrokerSyntheticRecords, *ciBrokerSyntheticDestination, *ciBrokerSyntheticResolver, generated.Plan, generated.ExecutorLease) {
	t.Helper()
	digest := hostaction.Digest("fixture")
	now := time.Now().UTC()
	at := now.Format(time.RFC3339)
	records := &ciBrokerSyntheticRecords{policy: store.CIExternalDeploymentPolicy{Binding: generated.CiExternalDeploymentBinding{BindingID: "deployment-one", ServiceID: "service-a", ExecutorID: "executor-a", MaterialVersion: "v1"}, Definition: generated.ServiceDefinition{ServiceID: "service-a", HostID: "application-a", HostIdentityDigest: digest}, Artifact: generated.ServiceDeploymentArtifact{Digest: digest}, ReferenceID: "hosting-key", ResolverID: "fixture-resolver"}, profile: store.GateAppliedProfile{ProfileID: "profile-a", StateRevision: 1, RecoveryEpoch: 2, Capabilities: []string{"credential.hosting.deploy"}}, reference: generated.CredentialReference{ReferenceID: "hosting-key", ConsumerID: "hosting.coolify.deploy", PurposeID: "hosting-deploy", TargetID: "service-a", ResolverID: "fixture-resolver", MaterialVersion: "v1", Status: "active", ActivatedAt: &at, StateRevision: 1, RecoveryEpoch: 2, VerifiedConsumerIDs: []string{"hosting.coolify.deploy"}}}
	op := generated.PlanOperation{Sequence: 1, OperationID: store.CIExternalDeploymentOperationID, OperationType: store.CIExternalDeploymentOperation, AdapterID: store.CIExternalDeploymentAdapter, TargetID: "service-a", ArtifactDigest: digest, ExecutorID: "executor-a"}
	plan := generated.Plan{PlanID: "child-plan", PlanDigest: digest, Binding: generated.PlanBinding{StateRevision: 3, RecoveryEpoch: 2}, Operations: []generated.PlanOperation{op}}
	lease := generated.ExecutorLease{LeaseID: "child-lease", Status: "active", PlanID: plan.PlanID, PlanDigest: plan.PlanDigest, RunID: "child-run", StepID: "child-step", BindingDigest: digest, OperationID: op.OperationID, TargetID: op.TargetID, AdapterID: op.AdapterID, ArtifactDigest: digest, ExecutorID: "executor-a", LeaseExpiresAt: now.Add(time.Minute).Format(time.RFC3339), MaximumExpiresAt: now.Add(time.Minute).Format(time.RFC3339), RecoveryEpoch: 2}
	records.lease = lease
	destination := &ciBrokerSyntheticDestination{snapshot: store.HostAdmissionSnapshot{Host: generated.ManagedHost{HostID: "application-a"}, IdentityDigest: digest, Profile: generated.HostProfile{RoleID: "application"}, Revision: store.RevisionToken{StateRevision: 3, RecoveryEpoch: 2}}}
	resolver := &ciBrokerSyntheticResolver{}
	registry := adapter.NewRegistry()
	if e := registry.RegisterCredentialResolver(adapter.CredentialCapabilityScope{ResolverID: "fixture-resolver", ConsumerID: "hosting.coolify.deploy", ProfileID: "profile-a", CapabilityID: "credential.hosting.deploy", Enabled: true}, resolver); e != nil {
		t.Fatal(e)
	}
	return &ciDeploymentBroker{records: records, registry: registry, destination: destination}, records, destination, resolver, plan, lease
}
func TestCIManagedDestinationDenialPreventsCredentialAndProviderBoundary(t *testing.T) {
	for _, state := range []string{"stale", "failed", "unadmitted"} {
		t.Run(state, func(t *testing.T) {
			broker, records, destination, resolver, plan, lease := ciBrokerDestinationFixture(t)
			destination.err = errors.New("synthetic destination " + state)
			providerCalls := 0
			value, e := broker.ResolveAndConsume(context.Background(), adapter.ExactExecutionBinding{}, plan, lease)
			if e == nil {
				providerCalls++
				value.Close()
			}
			if e == nil || resolver.calls != 0 || records.consumed != 0 || providerCalls != 0 {
				t.Fatalf("denied application destination reached credential/provider boundary: error=%v resolutions=%d consumed=%d provider=%d destinationChecks=%d", e, resolver.calls, records.consumed, providerCalls, destination.calls)
			}
		})
	}
}
func TestCIManagedHealthyExactApplicationDestinationStillWorks(t *testing.T) {
	broker, records, destination, resolver, plan, lease := ciBrokerDestinationFixture(t)
	value, e := broker.ResolveAndConsume(context.Background(), adapter.ExactExecutionBinding{}, plan, lease)
	if e != nil || resolver.calls != 1 || records.consumed != 1 || len(value.Bytes()) == 0 {
		t.Fatal(e, resolver.calls, records.consumed)
	}
	defer value.Close()
	if destination.calls == 0 || destination.requested != "application-a" {
		t.Fatal("CI execution identity substituted for application destination", destination.calls, destination.requested)
	}
}

func TestCIManagedDestinationBindingAndMissingVerifierDeny(t *testing.T) {
	for _, fault := range []string{"host", "identity", "role", "epoch", "service", "missing-verifier"} {
		t.Run(fault, func(t *testing.T) {
			broker, records, destination, resolver, plan, lease := ciBrokerDestinationFixture(t)
			switch fault {
			case "host":
				destination.snapshot.Host.HostID = "different-application"
			case "identity":
				destination.snapshot.IdentityDigest = hostaction.Digest("replacement")
			case "role":
				destination.snapshot.Profile.RoleID = "ci"
			case "epoch":
				destination.snapshot.Revision.RecoveryEpoch++
			case "service":
				records.policy.Binding.ServiceID = "different-service"
			case "missing-verifier":
				broker.destination = nil
			}
			value, e := broker.ResolveAndConsume(context.Background(), adapter.ExactExecutionBinding{}, plan, lease)
			value.Close()
			if e == nil || resolver.calls != 0 || records.consumed != 0 {
				t.Fatal(fault, e, resolver.calls, records.consumed)
			}
		})
	}
}
func TestCIManagedDestinationInvalidatedDuringResolutionClosesBeforeHandoff(t *testing.T) {
	broker, records, destination, resolver, plan, lease := ciBrokerDestinationFixture(t)
	resolver.onResolve = func() { destination.err = errors.New("synthetic baseline invalidated") }
	value, e := broker.ResolveAndConsume(context.Background(), adapter.ExactExecutionBinding{}, plan, lease)
	if e == nil || value != nil || resolver.calls != 1 || records.consumed != 0 || len(resolver.value.Bytes()) != 0 {
		t.Fatal(e, value, resolver.calls, records.consumed)
	}
}
func TestCIManagedDestinationRecheckedBeforeEachProviderPermission(t *testing.T) {
	broker, _, destination, _, plan, lease := ciBrokerDestinationFixture(t)
	value, e := broker.ResolveAndConsume(context.Background(), adapter.ExactExecutionBinding{}, plan, lease)
	if e != nil {
		t.Fatal(e)
	}
	defer value.Close()
	providerCalls := 0
	permission := func() {
		if broker.Check(context.Background(), adapter.ExactExecutionBinding{}, plan, lease) == nil {
			providerCalls++
		}
	}
	permission()
	if providerCalls != 1 {
		t.Fatal("healthy exact destination denied")
	}
	destination.err = errors.New("synthetic failed latest baseline")
	permission()
	permission()
	if providerCalls != 1 {
		t.Fatal("provider permitted after destination failed", providerCalls)
	}
}
