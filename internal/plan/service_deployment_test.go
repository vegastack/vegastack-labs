package plan

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
	"strings"
	"testing"
)

func TestDeploymentReadablePlanContainsExactReviewScope(t *testing.T) {
	in := generated.ServiceDeploymentRequest{Definition: generated.ServiceDefinition{ServiceID: "service-a", EnvironmentID: "production", HostID: "host-a"}, Action: "rollback", Artifact: generated.ServiceDeploymentArtifact{Repository: "registry.example.test/team/app", Digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, Binding: generated.ServiceDeploymentBinding{ConfigurationDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", DataPolicy: "compatible"}, ExpectedDeploymentRevision: 7}
	text := readablePlan(generated.Plan{ServiceDeployment: &in})
	for _, wanted := range []string{"service-a in production: rollback", in.Artifact.Repository + "@" + in.Artifact.Digest, "on host host-a", in.Binding.ConfigurationDigest, "data policy: compatible", "previous deployment revision: 7"} {
		if !strings.Contains(text, wanted) {
			t.Fatalf("review missing %q: %s", wanted, text)
		}
	}
}
