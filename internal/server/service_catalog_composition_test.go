package server

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter/coolify"
	"github.com/vegastack/vegastack-labs/internal/adapter/harbor"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/store"
)

func TestServiceObservationProjectsIndependentFailuresAndTrustLimits(t *testing.T) {
	def := generated.ServiceDefinition{ServiceID: "service-a", BindingDigest: "sha256:" + strings.Repeat("a", 64)}
	revision := store.RevisionToken{StateRevision: 12, RecoveryEpoch: 2}
	hosting := coolify.ApplicationSnapshot{ProviderStatus: "running:healthy", ConfiguredImageName: "registry.example/project/app", ConfiguredImageTag: "v1"}
	artifact := harbor.ArtifactSnapshot{Digest: "sha256:" + strings.Repeat("b", 64), Kind: "index", ScanState: "passed"}
	unavailable := serviceUnavailable(failure.New(generated.ErrorCodeDependencyUnavailable, "provider", false), false)
	cases := []struct {
		name                    string
		hostingErr, artifactErr error
		configured              bool
		hosting, artifact       string
	}{{"both-observed", nil, nil, true, "observed", "observed"}, {"hosting-unavailable", unavailable, nil, true, "unavailable", "observed"}, {"registry-unavailable", nil, unavailable, true, "observed", "unavailable"}, {"registry-not-configured", nil, nil, false, "observed", "not-configured"}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := serviceObservation(def, revision, hosting, tc.hostingErr, &artifact, tc.artifactErr, tc.configured)
			if out.HostingState != tc.hosting || out.ArtifactState != tc.artifact || out.SignatureState != "unverified" || out.ProvenanceState != "unverified" || out.RunningDigestState != "unknown" || out.HealthState != "unknown" || out.HostAdmission != "not-verified" {
				t.Fatalf("projection=%+v", out)
			}
			if out.StateRevision != 12 || out.RecoveryEpoch != 2 {
				t.Fatal(out)
			}
			if tc.hostingErr != nil && (out.ConfiguredImage != "" || out.ProviderStatus != "unknown") {
				t.Fatal("failed hosting leaked retained snapshot", out)
			}
			if (!tc.configured || tc.artifactErr != nil) && (out.ArtifactDigest != "" || out.ScanState != "unknown") {
				t.Fatal("failed artifact retained observation", out)
			}
			raw, _ := json.Marshal(out)
			if err := generated.ValidateContractJSON(generated.SchemaIDServiceObservation, raw, generated.ContractExact); err != nil {
				t.Fatalf("invalid projection %s err=%v", raw, err)
			}
		})
	}
}
func TestServiceSnapshotDigestExcludesClockButBindsObservedStateAndCredential(t *testing.T) {
	initial := serviceProviderSnapshot{Hosting: coolify.ApplicationSnapshot{ApplicationUUID: "app-a", ProviderStatus: "running"}, Artifact: &harbor.ArtifactSnapshot{Digest: "sha256:" + strings.Repeat("a", 64), Kind: "index", ScanState: "passed", ObservedAt: time.Now()}, Credentials: []serviceCredentialIdentity{{ReferenceID: "hosting-ref", ConsumerID: "hosting.coolify", MaterialVersion: "v1", RecoveryEpoch: 1}}}
	digest := serviceSnapshotDigest(initial)
	initial.Artifact.ObservedAt = initial.Artifact.ObservedAt.Add(time.Hour)
	if serviceSnapshotDigest(initial) != digest {
		t.Fatal("timestamp staled service snapshot")
	}
	if initial.Artifact.ObservedAt.IsZero() {
		t.Fatal("digest mutated supplied observation")
	}
	initial.Credentials[0].MaterialVersion = "v2"
	if serviceSnapshotDigest(initial) == digest {
		t.Fatal("credential rotation did not stale snapshot")
	}
	initial.Credentials[0].MaterialVersion = "v1"
	initial.Hosting.ProviderStatus = "stopped"
	if serviceSnapshotDigest(initial) == digest {
		t.Fatal("provider drift did not stale snapshot")
	}
	initial.Hosting.ProviderStatus = "running"
	initial.Artifact.ScanState = "findings"
	if serviceSnapshotDigest(initial) == digest {
		t.Fatal("scan drift did not stale snapshot")
	}
}
func TestServiceProviderReasonsNeverEchoPrivateErrors(t *testing.T) {
	for _, code := range []string{generated.ErrorCodeAuthenticationRequired, generated.ErrorCodeAuthorizationDenied, generated.ErrorCodeResourceNotFound, generated.ErrorCodeIntegrityFailure, generated.ErrorCodePlanStale, generated.ErrorCodePrerequisiteBlocked, generated.ErrorCodeRecoveryEpochMismatch, generated.ErrorCodeRateLimited} {
		reason := serviceProviderReason(failure.New(code, "private-reference-and-provider-url", false))
		if reason == "" || strings.Contains(reason, "private") || strings.Contains(reason, "https") {
			t.Fatal(reason)
		}
	}
}
func TestServiceProfileDigestIgnoresCurrentRevisionAndCapabilityOrder(t *testing.T) {
	scope := store.GateAppliedProfile{ProfileID: "profile-a", ProfileVersion: "v1", PolicyID: "policy-a", PolicyVersion: "v1", Capabilities: []string{"credential.registry.read", "credential.hosting.read"}, StateRevision: 5, RecoveryEpoch: 2}
	digest := serviceProfileDigest(scope)
	scope.StateRevision = 10
	scope.Capabilities = []string{"credential.hosting.read", "credential.registry.read"}
	if serviceProfileDigest(scope) != digest {
		t.Fatal("unrelated revision stales binding")
	}
	scope.RecoveryEpoch++
	if serviceProfileDigest(scope) == digest {
		t.Fatal("epoch drift ignored")
	}
}

func TestServicePolicyBindsFrozenProtectedConfiguration(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	binding := generated.ServiceProviderBinding{Schema: generated.SchemaIDServiceProviderBinding, SchemaVersion: "1.0.0", BindingID: "binding-a", ServiceID: "service-a", EnvironmentID: "environment-a", OwnerID: "human-a", HostID: "host-a", HostIdentityDigest: digest, Coolify: &generated.CoolifyServiceBinding{Schema: generated.SchemaIDCoolifyServiceBinding, SchemaVersion: "1.0.0", Origin: "https://hosting.example/api/v1", TeamID: 1, ProjectID: 2, EnvironmentID: 3, DestinationID: 4, ProjectUUID: "project-a", Environment: "production", ApplicationUUID: "app-a", DestinationType: `App\Models\StandaloneDocker`, ObservationReferenceID: "hosting-ref"}}
	policies, err := servicePolicies([]generated.ServiceProviderBinding{binding})
	if err != nil || len(policies) != 1 {
		t.Fatalf("policies=%+v err=%v", policies, err)
	}
	original := policies[0]
	binding.Coolify.ApplicationUUID = "app-b"
	if policies[0] != original {
		t.Fatal("caller mutation changed derived policy")
	}
	changed, err := servicePolicies([]generated.ServiceProviderBinding{binding})
	if err != nil || changed[0].Definition.BindingDigest == original.Definition.BindingDigest || changed[0].ResourceKeyDigest == original.ResourceKeyDigest {
		t.Fatal("provider resource change not bound", err)
	}
	source := &serviceCatalogComposition{bindings: map[string]generated.ServiceProviderBinding{binding.BindingID: binding}}
	if _, err := source.binding(original.Definition); err == nil {
		t.Fatal("configuration drift accepted")
	}
}
func TestServiceCurrentAuthorityFailuresCannotBecomeProviderStatus(t *testing.T) {
	for _, code := range []string{generated.ErrorCodeAuthorizationDenied, generated.ErrorCodeAuthenticationRequired, generated.ErrorCodeRecoveryEpochMismatch, generated.ErrorCodePlanStale} {
		if serviceDisplayable(serviceFailure(code)) {
			t.Fatalf("%s became provider outage", code)
		}
	}
	provider := serviceUnavailable(serviceFailure(generated.ErrorCodeAuthorizationDenied), false)
	credential := serviceUnavailable(serviceFailure(generated.ErrorCodePrerequisiteBlocked), true)
	if !serviceDisplayable(provider) || serviceProviderReason(provider) != "provider-unavailable" || !serviceDisplayable(credential) || serviceProviderReason(credential) != "credential-unavailable" {
		t.Fatal("explicit provider/credential outages lost")
	}
}
