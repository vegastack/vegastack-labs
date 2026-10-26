package serverconfig

import (
	"reflect"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

func deploymentBindingFixture() (generated.ServiceDeploymentProviderBinding, generated.ServiceProviderBinding) {
	service := serviceBindingFixture()
	service.Harbor = &generated.HarborServiceBinding{Schema: generated.SchemaIDHarborServiceBinding, SchemaVersion: "1.0.0", Origin: "https://registry.example", Project: "project", Repository: "app", ArtifactDigest: "sha256:" + strings.Repeat("a", 64), RobotUsername: "robot$project+observe", ObservationReferenceID: "harbor-read"}
	binding := generated.ServiceDeploymentProviderBinding{Schema: generated.SchemaIDServiceDeploymentProviderBinding, SchemaVersion: "1.0.0", Binding: generated.ServiceDeploymentBinding{Schema: generated.SchemaIDServiceDeploymentBinding, SchemaVersion: "1.0.0", ServiceID: service.ServiceID, BindingID: service.BindingID, DataPolicy: "stateless"}, ServiceBindingID: service.BindingID, DestinationUUID: "destination-one", ServerUUID: "server-one", ServerID: 5, MutationReferenceID: "mutation-one", RuntimeReferenceID: "runtime-one", ExclusiveOwnership: true, Artifacts: []generated.ServiceDeploymentArtifactSource{{Schema: generated.SchemaIDServiceDeploymentArtifactSource, SchemaVersion: "1.0.0", ArtifactID: "image-one", Repository: "registry.example/project/app", Digest: "sha256:" + strings.Repeat("a", 64), ManifestPath: "/protected/image.manifest", BundlePath: "/protected/image.bundle", PolicyPath: "/protected/trust.policy"}}}
	return binding, service
}
func TestFreezeDeploymentBindingsComputesStableProtectedConfiguration(t *testing.T) {
	input, service := deploymentBindingFixture()
	freeze := func(b generated.ServiceDeploymentProviderBinding) generated.ServiceDeploymentProviderBinding {
		t.Helper()
		out, e := FreezeDeploymentBindings([]generated.ServiceDeploymentProviderBinding{b}, []generated.ServiceProviderBinding{service})
		if e != nil || len(out) != 1 {
			t.Fatalf("freeze: %v", e)
		}
		return out[0]
	}
	first := freeze(input)
	if len(first.Binding.ConfigurationDigest) != 71 || !strings.HasPrefix(first.Binding.ConfigurationDigest, "sha256:") {
		t.Fatal("missing computed configuration digest")
	}
	input.Binding.ConfigurationDigest = "sha256:" + strings.Repeat("f", 64)
	if next := freeze(input); !reflect.DeepEqual(next, first) {
		t.Fatal("caller digest changed server-computed configuration")
	}
	for name, change := range map[string]func(*generated.ServiceDeploymentProviderBinding){
		"server":              func(b *generated.ServiceDeploymentProviderBinding) { b.ServerUUID = "server-two" },
		"server-id":           func(b *generated.ServiceDeploymentProviderBinding) { b.ServerID++ },
		"destination":         func(b *generated.ServiceDeploymentProviderBinding) { b.DestinationUUID = "destination-two" },
		"mutation-credential": func(b *generated.ServiceDeploymentProviderBinding) { b.MutationReferenceID = "mutation-two" },
		"runtime-credential":  func(b *generated.ServiceDeploymentProviderBinding) { b.RuntimeReferenceID = "runtime-two" },
		"artifact": func(b *generated.ServiceDeploymentProviderBinding) {
			b.Artifacts[0].Digest = "sha256:" + strings.Repeat("b", 64)
		},
		"trust-policy": func(b *generated.ServiceDeploymentProviderBinding) {
			b.Artifacts[0].PolicyPath = "/protected/other.policy"
		},
		"data-policy": func(b *generated.ServiceDeploymentProviderBinding) { b.Binding.DataPolicy = "compatible" },
	} {
		t.Run(name, func(t *testing.T) {
			b, _ := deploymentBindingFixture()
			change(&b)
			if freeze(b).Binding.ConfigurationDigest == first.Binding.ConfigurationDigest {
				t.Fatal("changed protected configuration preserved digest")
			}
		})
	}
	input.Artifacts[0].PolicyPath = "/changed"
	if first.Artifacts[0].PolicyPath != "/protected/trust.policy" {
		t.Fatal("frozen artifact configuration aliases caller memory")
	}
	// Different artifacts may deliberately share the same local trusted policy.
	shared, _ := deploymentBindingFixture()
	other := shared.Artifacts[0]
	other.ArtifactID = "image-two"
	other.Digest = "sha256:" + strings.Repeat("b", 64)
	other.ManifestPath = "/protected/other.manifest"
	other.BundlePath = "/protected/other.bundle"
	shared.Artifacts = append(shared.Artifacts, other)
	_ = freeze(shared)
}
func TestFreezeDeploymentBindingsRejectsUnsupportedOrUnboundTargets(t *testing.T) {
	for name, change := range map[string]func(*generated.ServiceDeploymentProviderBinding, *generated.ServiceProviderBinding){
		"swarm": func(_ *generated.ServiceDeploymentProviderBinding, s *generated.ServiceProviderBinding) {
			s.Coolify.DestinationType = "App\\Models\\SwarmDocker"
		},
		"missing-harbor": func(_ *generated.ServiceDeploymentProviderBinding, s *generated.ServiceProviderBinding) {
			s.Harbor = nil
		},
		"wrong-service": func(b *generated.ServiceDeploymentProviderBinding, _ *generated.ServiceProviderBinding) {
			b.Binding.ServiceID = "other-service"
		},
		"wrong-binding": func(b *generated.ServiceDeploymentProviderBinding, _ *generated.ServiceProviderBinding) {
			b.ServiceBindingID = "other-binding"
		},
		"not-exclusive": func(b *generated.ServiceDeploymentProviderBinding, _ *generated.ServiceProviderBinding) {
			b.ExclusiveOwnership = false
		},
		"wrong-origin": func(b *generated.ServiceDeploymentProviderBinding, _ *generated.ServiceProviderBinding) {
			b.Artifacts[0].Repository = "other.example/project/app"
		},
		"wrong-repository": func(b *generated.ServiceDeploymentProviderBinding, _ *generated.ServiceProviderBinding) {
			b.Artifacts[0].Repository = "registry.example/project/other"
		},
		"relative-path": func(b *generated.ServiceDeploymentProviderBinding, _ *generated.ServiceProviderBinding) {
			b.Artifacts[0].ManifestPath = "relative.manifest"
		},
		"nul-path": func(b *generated.ServiceDeploymentProviderBinding, _ *generated.ServiceProviderBinding) {
			b.Artifacts[0].BundlePath = "/protected/bundle\x00"
		},
		"duplicate-artifact": func(b *generated.ServiceDeploymentProviderBinding, _ *generated.ServiceProviderBinding) {
			b.Artifacts = append(b.Artifacts, b.Artifacts[0])
		},
		"bad-sha": func(b *generated.ServiceDeploymentProviderBinding, _ *generated.ServiceProviderBinding) {
			b.Artifacts[0].Digest = "sha256:" + strings.Repeat("g", 64)
		},
		"short-sha": func(b *generated.ServiceDeploymentProviderBinding, _ *generated.ServiceProviderBinding) {
			b.Artifacts[0].Digest = "sha256:abcd"
		},
	} {
		t.Run(name, func(t *testing.T) {
			b, s := deploymentBindingFixture()
			change(&b, &s)
			if out, e := FreezeDeploymentBindings([]generated.ServiceDeploymentProviderBinding{b}, []generated.ServiceProviderBinding{s}); e == nil || out != nil {
				t.Fatal("invalid target accepted")
			}
		})
	}
	b, s := deploymentBindingFixture()
	if _, e := FreezeDeploymentBindings([]generated.ServiceDeploymentProviderBinding{b, b}, []generated.ServiceProviderBinding{s}); e == nil {
		t.Fatal("duplicate service ownership accepted")
	}
}
