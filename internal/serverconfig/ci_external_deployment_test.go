package serverconfig

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
	"testing"
)

func TestCIExternalDeploymentRejectsCrossWiringAndUnsupportedScope(t *testing.T) {
	for _, fault := range []string{"none", "executor", "artifact", "resolver", "duplicate", "private-origin", "http", "invalid-settings"} {
		t.Run(fault, func(t *testing.T) {
			d, s := deploymentBindingFixture()
			d.Configuration = &generated.ServiceConfiguration{Schema: generated.SchemaIDServiceConfiguration, SchemaVersion: "1.0.0", EnvironmentClass: "development", CPUQuotaPercent: 100, MemoryBytes: 268435456, Port: 8080, Exposure: "private", HealthPath: "/ready", HealthExpectedStatus: 200, HealthIntervalSeconds: 10, HealthTimeoutSeconds: 2, HealthRetries: 3, DataClass: "stateless", Migration: "none", Rollback: "previous-artifact", SecretReferenceIDs: []string{}}
			j := ciJobBindingFixture()
			s.Coolify.Origin = "https://deploy.example"
			b := generated.CiExternalDeploymentBinding{Schema: generated.SchemaIDCiExternalDeploymentBinding, SchemaVersion: "1.0.0", BindingID: "external-a", ExecutionBindingID: j.BindingID, ServiceID: s.ServiceID, ArtifactID: d.Artifacts[0].ArtifactID, ExecutorID: j.AutomationPrincipalID, MaterialVersion: "v1", ResolverID: "resolver-a"}
			switch fault {
			case "executor":
				b.ExecutorID = "foreign"
			case "artifact":
				b.ArtifactID = "foreign"
			case "resolver":
				b.ResolverID = ""
			case "private-origin":
				s.Coolify.Origin = "https://192.168.88.1"
			case "http":
				s.Coolify.Origin = "http://deploy.example"
			case "invalid-settings":
				d.Configuration = &generated.ServiceConfiguration{}
			}
			inputs := []generated.CiExternalDeploymentBinding{b}
			if fault == "duplicate" {
				inputs = append(inputs, b)
			}
			out, err := FreezeCIExternalDeployments(inputs, []generated.CiJobExecutionBinding{j}, []generated.ServiceProviderBinding{s}, []generated.ServiceDeploymentProviderBinding{d})
			if fault == "none" {
				if err != nil || len(out) != 1 {
					t.Fatal(err)
				}
				inputs[0].ArtifactID = "changed"
				if out[0].ArtifactID != b.ArtifactID {
					t.Fatal("aliased input")
				}
			} else if err == nil {
				t.Fatal("unsupported binding accepted")
			}
		})
	}
}
