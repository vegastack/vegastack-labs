package credentialref

import (
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

func TestLifecycleTargetDigestSealsMetadataAndNormalizesSets(t *testing.T) {
	draft := "draft-a"
	input := generated.CredentialLifecycleRequest{Schema: generated.SchemaIDCredentialLifecycleRequest, SchemaVersion: "1.2.0", Action: "credential.stage", DraftID: &draft, ReferenceID: "reference-a", ConsumerIDs: []string{"consumer-b", "consumer-a"}, RequiredDeniedConsumerIDs: []string{}, MaterialVersion: "version-a", ResolverID: "native-systemd", TargetID: "target-a", ExpectedStateRevision: 3, RecoveryEpoch: 1, IdempotencyKey: "key-a"}
	digest := LifecycleTargetDigest(input)
	if digest == "" {
		t.Fatal("a digest must be calculable before targetDigest is populated")
	}
	input.TargetDigest = digest
	input.ConsumerIDs = []string{"consumer-a", "consumer-b"}
	if LifecycleTargetDigest(input) != digest {
		t.Fatal("set ordering changed target identity")
	}
	input.MaterialVersion = "version-b"
	if LifecycleTargetDigest(input) == digest {
		t.Fatal("material substitution retained target identity")
	}
	input.ConsumerIDs = []string{"consumer-a", "consumer-a"}
	if LifecycleTargetDigest(input) != "" {
		t.Fatal("invalid metadata had a target digest")
	}
}
