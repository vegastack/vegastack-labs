package credentialref

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

// ImportTargetDigest seals only public, exact draft metadata. Never include a
// private value or a digest derived from plaintext in this binding.
func ImportTargetDigest(input generated.CredentialImportRequest) string {
	for _, id := range []string{input.ReferenceID, input.ConsumerID, input.PurposeID, input.TargetID, input.ResolverID, input.MaterialVersion} {
		if _, err := ParseID(id); err != nil {
			return ""
		}
	}
	if input.ExpectedStateRevision < 0 || input.RecoveryEpoch < 0 {
		return ""
	}
	parts := []string{"credential-import-target-v1", input.ReferenceID, input.ConsumerID, input.PurposeID, input.TargetID, input.ResolverID, input.MaterialVersion, strconv.FormatInt(input.ExpectedStateRevision, 10), strconv.FormatInt(input.RecoveryEpoch, 10)}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return "sha256:" + hex.EncodeToString(sum[:])
}
