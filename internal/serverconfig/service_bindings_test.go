package serverconfig

import (
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

func serviceBindingFixture() generated.ServiceProviderBinding {
	return generated.ServiceProviderBinding{Schema: generated.SchemaIDServiceProviderBinding, SchemaVersion: "1.0.0", BindingID: "binding-one", ServiceID: "service-one", EnvironmentID: "preview", OwnerID: "owner-one", HostID: "host-one", HostIdentityDigest: "sha256:" + strings.Repeat("a", 64), Coolify: &generated.CoolifyServiceBinding{Schema: generated.SchemaIDCoolifyServiceBinding, SchemaVersion: "1.0.0", Origin: "https://coolify.example/api/v1", TeamID: 1, ProjectID: 2, EnvironmentID: 3, DestinationID: 4, ProjectUUID: "project-one", Environment: "preview", ApplicationUUID: "application-one", DestinationType: "App\\Models\\StandaloneDocker", ObservationReferenceID: "coolify-read"}}
}

func TestServiceBindingsFreezeTargetsAndRejectAmbiguousOwnership(t *testing.T) {
	input := []generated.ServiceProviderBinding{serviceBindingFixture()}
	got, err := FreezeServiceBindings(input)
	if err != nil || len(got) != 1 {
		t.Fatalf("freeze: %v", err)
	}
	input[0].Coolify.Origin = "https://changed.example/api/v1"
	if got[0].Coolify.Origin != "https://coolify.example/api/v1" {
		t.Fatal("binding shared mutable provider target")
	}
	for _, change := range []func(*generated.ServiceProviderBinding){
		func(b *generated.ServiceProviderBinding) { b.BindingID = "binding-two" },
		func(b *generated.ServiceProviderBinding) { b.BindingID = "binding-two"; b.ServiceID = "service-two" },
	} {
		a, b := serviceBindingFixture(), serviceBindingFixture()
		change(&b)
		if _, err := FreezeServiceBindings([]generated.ServiceProviderBinding{a, b}); err == nil {
			t.Fatal("duplicate service/resource ownership accepted")
		}
	}
}

func TestServiceBindingsRejectUnboundedOrUnsafeProfileTargets(t *testing.T) {
	for name, change := range map[string]func(*generated.ServiceProviderBinding){
		"http": func(b *generated.ServiceProviderBinding) { b.Coolify.Origin = "http://coolify.example/api/v1" },
		"url-credential": func(b *generated.ServiceProviderBinding) {
			b.Coolify.Origin = "https://user:password@coolify.example/api/v1"
		},
		"query":             func(b *generated.ServiceProviderBinding) { b.Coolify.Origin += "?token=private-canary" },
		"other-path":        func(b *generated.ServiceProviderBinding) { b.Coolify.Origin = "https://coolify.example/api/v1/servers" },
		"missing-reference": func(b *generated.ServiceProviderBinding) { b.Coolify.ObservationReferenceID = "" },
		"zero-team":         func(b *generated.ServiceProviderBinding) { b.Coolify.TeamID = 0 },
		"wrong-destination": func(b *generated.ServiceProviderBinding) { b.Coolify.DestinationType = "arbitrary" },
		"missing-host":      func(b *generated.ServiceProviderBinding) { b.HostID = "" },
		"missing-provider":  func(b *generated.ServiceProviderBinding) { b.Coolify = nil },
	} {
		t.Run(name, func(t *testing.T) {
			b := serviceBindingFixture()
			change(&b)
			if _, err := FreezeServiceBindings([]generated.ServiceProviderBinding{b}); err == nil {
				t.Fatal("unsafe binding accepted")
			}
		})
	}
	if _, err := FreezeServiceBindings(make([]generated.ServiceProviderBinding, 129)); err == nil {
		t.Fatal("unbounded bindings accepted")
	}
}
