package credentialref

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

// LifecycleTargetDigest seals public lifecycle metadata without credential
// material or a client-supplied ciphertext fingerprint.
func LifecycleTargetDigest(input generated.CredentialLifecycleRequest) string {
	validated := input
	validated.TargetDigest = "sha256:" + strings.Repeat("0", 64)
	if generated.ValidateLifecycleRequestSemantics(validated) != nil {
		return ""
	}
	parts := []string{"credential-lifecycle-target-v1", input.Action, canonicalStringPointer(input.DraftID), input.ReferenceID, canonicalIDSet(input.ConsumerIDs), canonicalIDSet(input.RequiredDeniedConsumerIDs), input.MaterialVersion, canonicalStringPointer(input.PriorMaterialVersion), input.ResolverID, input.TargetID, strconv.FormatInt(input.OverlapSeconds, 10), strconv.FormatInt(input.ExpectedStateRevision, 10), strconv.FormatInt(input.RecoveryEpoch, 10), canonicalInt64Pointer(input.PriorRecoveryEpoch), canonicalStringPointer(input.CustodyProofDigest), canonicalStringPointer(input.FormerControllerFenceDigest)}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return "sha256:" + hex.EncodeToString(sum[:])
}
