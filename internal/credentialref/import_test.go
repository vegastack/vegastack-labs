package credentialref

import (
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

func TestImportTargetDigestBindsOnlyValidatedPublicMetadata(t *testing.T) {
	request := generated.CredentialImportRequest{ReferenceID: "reference-a", ConsumerID: "consumer-a", PurposeID: "purpose-a", TargetID: "target-a", ResolverID: "native-systemd", MaterialVersion: "version-a", ExpectedStateRevision: 7, RecoveryEpoch: 2}
	first := ImportTargetDigest(request)
	if !strings.HasPrefix(first, "sha256:") || len(first) != 71 {
		t.Fatalf("digest=%q", first)
	}
	request.ConsumerID = "consumer-b"
	if ImportTargetDigest(request) == first {
		t.Fatal("consumer was not bound")
	}
	request.ConsumerID = "../unsafe"
	if ImportTargetDigest(request) != "" {
		t.Fatal("invalid public metadata produced a digest")
	}
}
