package server

import (
	"context"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/servicecatalog"
	"github.com/vegastack/vegastack-labs/internal/store"
)

func deploymentCompositionProfile() serverconfig.Profile {
	digest := "sha256:" + strings.Repeat("a", 64)
	service := generated.ServiceProviderBinding{Schema: generated.SchemaIDServiceProviderBinding, SchemaVersion: "1.0.0", BindingID: "binding-a", ServiceID: "service-a", EnvironmentID: "preview", OwnerID: "human-a", HostID: "host-a", HostIdentityDigest: digest, Coolify: &generated.CoolifyServiceBinding{Schema: generated.SchemaIDCoolifyServiceBinding, SchemaVersion: "1.0.0", Origin: "https://coolify.example/api/v1", TeamID: 1, ProjectID: 2, EnvironmentID: 3, DestinationID: 4, ProjectUUID: "project-a", Environment: "preview", ApplicationUUID: "app-a", DestinationType: `App\Models\StandaloneDocker`, ObservationReferenceID: "hosting-read"}, Harbor: &generated.HarborServiceBinding{Schema: generated.SchemaIDHarborServiceBinding, SchemaVersion: "1.0.0", Origin: "https://registry.example", Project: "project", Repository: "app", ArtifactDigest: digest, RobotUsername: "robot$observe", ObservationReferenceID: "registry-read"}}
	deployment := generated.ServiceDeploymentProviderBinding{Schema: generated.SchemaIDServiceDeploymentProviderBinding, SchemaVersion: "1.0.0", Binding: generated.ServiceDeploymentBinding{Schema: generated.SchemaIDServiceDeploymentBinding, SchemaVersion: "1.0.0", ServiceID: "service-a", BindingID: "binding-a", DataPolicy: "stateless"}, ServiceBindingID: "binding-a", DestinationUUID: "destination-a", ServerUUID: "server-a", ServerID: 5, MutationReferenceID: "hosting-mutate", RuntimeReferenceID: "runtime-read", ExclusiveOwnership: true, Artifacts: []generated.ServiceDeploymentArtifactSource{{Schema: generated.SchemaIDServiceDeploymentArtifactSource, SchemaVersion: "1.0.0", ArtifactID: "artifact-a", Repository: "registry.example/project/app", Digest: digest, ManifestPath: "/protected/manifest", BundlePath: "/protected/bundle", PolicyPath: "/protected/policy"}}}
	return serverconfig.Profile{ServiceBindings: []generated.ServiceProviderBinding{service}, ServiceDeploymentBindings: []generated.ServiceDeploymentProviderBinding{deployment}}
}
func deploymentComposition(t *testing.T, p serverconfig.Profile) (*serviceDeploymentComposition, generated.ServiceDeploymentRequest) {
	t.Helper()
	service := p.ServiceBindings[0]
	base := &serviceCatalogComposition{store: &store.Store{}, bindings: map[string]generated.ServiceProviderBinding{service.BindingID: service}}
	c, e := newServiceDeploymentComposition(p, base)
	if e != nil {
		t.Fatal(e)
	}
	q := generated.ServiceDeploymentRequest{Definition: serviceBindingDefinition(service), Binding: c.bindings[service.ServiceID].Binding}
	return c, q
}
func TestServiceDeploymentCompositionRejectsMissingBase(t *testing.T) {
	for _, base := range []*serviceCatalogComposition{nil, {}} {
		if _, e := newServiceDeploymentComposition(serverconfig.Profile{}, base); e == nil {
			t.Fatal("missing store accepted")
		}
	}
}
func TestServiceDeploymentCompositionBindsExactProtectedSettings(t *testing.T) {
	p := deploymentCompositionProfile()
	c, q := deploymentComposition(t, p)
	if _, e := c.binding(q); e != nil {
		t.Fatal(e)
	}
	for name, change := range map[string]func(*serverconfig.Profile){
		"server":             func(p *serverconfig.Profile) { p.ServiceDeploymentBindings[0].ServerUUID = "server-b" },
		"mutation-reference": func(p *serverconfig.Profile) { p.ServiceDeploymentBindings[0].MutationReferenceID = "other-mutation" },
		"runtime-reference":  func(p *serverconfig.Profile) { p.ServiceDeploymentBindings[0].RuntimeReferenceID = "other-runtime" },
		"policy": func(p *serverconfig.Profile) {
			p.ServiceDeploymentBindings[0].Artifacts[0].PolicyPath = "/protected/other"
		},
		"destination": func(p *serverconfig.Profile) { p.ServiceDeploymentBindings[0].DestinationUUID = "destination-b" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := deploymentCompositionProfile()
			change(&changed)
			newComposition, _ := deploymentComposition(t, changed)
			if _, e := newComposition.binding(q); e == nil {
				t.Fatal("changed protected configuration accepted old request")
			}
		})
	}
	p.ServiceDeploymentBindings[0].ExclusiveOwnership = false
	if _, e := newServiceDeploymentComposition(p, c.base); e == nil {
		t.Fatal("shared provider writer ownership accepted")
	}
	q.Definition.OwnerID = "other-human"
	if _, e := c.binding(q); e == nil {
		t.Fatal("changed service definition accepted")
	}
}
func TestServiceDeploymentCompositionDeniesBeforeProviderAndArtifactProof(t *testing.T) {
	c, q := deploymentComposition(t, deploymentCompositionProfile())
	if out, e := c.Deploy(context.Background(), q, identity.Principal{}); e == nil || out.Status != "partial" || out.ProviderReceiptID != "" {
		t.Fatal("unauthenticated deploy accepted", out, e)
	}
	if e := c.artifact(context.Background(), q, c.bindings[q.Definition.ServiceID]); e == nil {
		t.Fatal("unconfigured artifact accepted")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	source := c.bindings[q.Definition.ServiceID].Artifacts[0]
	if sealed, e := deploymentArtifact(canceled, source, 0); e == nil || sealed != (generated.ServiceDeploymentArtifact{}) {
		t.Fatal("canceled artifact acquisition produced proof", sealed, e)
	}
	if policies, e := deploymentPolicies(canceled, deploymentCompositionProfile()); e == nil || len(policies) != 0 {
		t.Fatal("unread signed bytes became policy", policies, e)
	}
	// Caller supplied proof strings are never enough to select an artifact.
	q.Artifact = generated.ServiceDeploymentArtifact{ArtifactID: "other-artifact"}
	q.ArtifactProofDigest = servicecatalog.Digest(q.Artifact)
	if e := c.artifact(context.Background(), q, c.bindings[q.Definition.ServiceID]); e == nil {
		t.Fatal("caller proof admitted unknown artifact")
	}
}
