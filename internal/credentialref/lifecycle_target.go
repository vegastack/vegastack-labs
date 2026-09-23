package credentialref

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
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
	parts := []string{"credential-lifecycle-target-v2", input.Action, canonicalStringPointer(input.DraftID), input.ReferenceID, canonicalIDSet(input.ConsumerIDs), canonicalIDSet(input.RequiredDeniedConsumerIDs), canonicalPublicNativeConsumers(input.NativeConsumers), canonicalPublicDeniedReaders(input.NativeDeniedReaders), input.MaterialVersion, canonicalStringPointer(input.PriorMaterialVersion), input.ResolverID, input.TargetID, strconv.FormatInt(input.OverlapSeconds, 10), strconv.FormatInt(input.ExpectedStateRevision, 10), strconv.FormatInt(input.RecoveryEpoch, 10), canonicalInt64Pointer(input.PriorRecoveryEpoch), canonicalStringPointer(input.CustodyProofDigest), canonicalStringPointer(input.FormerControllerFenceDigest)}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func canonicalPublicNativeConsumers(values *[]generated.CredentialNativeConsumer) string {
	if values == nil {
		return ""
	}
	items := make([]string, 0, len(*values))
	for _, item := range *values {
		items = append(items, strings.Join([]string{item.ConsumerID, item.TargetID, item.HostMachineID, item.UnitName, strconv.FormatInt(item.ServiceUID, 10), strconv.FormatInt(item.ServiceGID, 10), item.ProfileID, item.RoleID}, "\x00"))
	}
	slices.Sort(items)
	return strings.Join(items, "\x01")
}

func canonicalPublicDeniedReaders(values *[]generated.CredentialNativeDeniedReader) string {
	if values == nil {
		return ""
	}
	items := make([]string, 0, len(*values))
	for _, item := range *values {
		items = append(items, strings.Join([]string{item.ConsumerID, item.TargetID, item.HostMachineID, strconv.FormatInt(item.ReaderUID, 10), strconv.FormatInt(item.ReaderGID, 10), item.ProfileID, item.RoleID}, "\x00"))
	}
	slices.Sort(items)
	return strings.Join(items, "\x01")
}
