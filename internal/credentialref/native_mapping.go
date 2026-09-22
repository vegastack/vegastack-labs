package credentialref

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

var (
	nativeMachineID = regexp.MustCompile(`^[0-9a-f]{32}$`)
	nativeUnitName  = regexp.MustCompile(`^[a-z0-9][a-z0-9_.@-]{0,119}\.service$`)
)

// NativeConsumerBinding is the plan-sealed claim that #141 must compare with
// the applied local systemd unit. It does not itself prove OS delivery.
type NativeConsumerBinding struct {
	ConsumerID, TargetID, HostMachineID, UnitName string
	ServiceUID, ServiceGID                        uint32
	ProfileID, RoleID, LoadedName                 string
}

// NativeDeniedReaderBinding names the exact physical identity #141 must use
// for a direct denied-read attempt. It is not a permission prediction.
type NativeDeniedReaderBinding struct {
	ConsumerID, TargetID, HostMachineID string
	ReaderUID, ReaderGID                uint32
	ProfileID, RoleID                   string
}

func LoadedNameForVersion(consumerID, referenceID, materialVersion string) string {
	for _, id := range []string{consumerID, referenceID, materialVersion} {
		if _, err := ParseID(id); err != nil {
			return ""
		}
	}
	sum := sha256.Sum256([]byte("native-loaded-credential-v1\x00" + consumerID + "\x00" + referenceID + "\x00" + materialVersion))
	return "credential-" + hex.EncodeToString(sum[:16])
}

func ValidNativeBindings(binding LifecycleBinding) bool {
	if binding.ResolverID != "native-systemd" || binding.Action != ActionActivate && binding.Action != ActionRotate {
		return binding.NativeArtifactConsumerID == "" && len(binding.NativeConsumers) == 0 && len(binding.NativeDeniedReaders) == 0
	}
	if _, err := ParseID(binding.NativeArtifactConsumerID); err != nil || !slices.Contains(binding.ConsumerIDs, binding.NativeArtifactConsumerID) {
		return false
	}
	if binding.Action == ActionRotate && (binding.ImportDraftConsumerID == nil || *binding.ImportDraftConsumerID != binding.NativeArtifactConsumerID) {
		return false
	}
	if len(binding.NativeConsumers) != len(binding.ConsumerIDs) || len(binding.NativeDeniedReaders) != len(binding.RequiredDeniedConsumerIDs) || len(binding.NativeConsumers) == 0 || len(binding.NativeConsumers) > MaxLifecycleConsumers || len(binding.NativeDeniedReaders) == 0 || len(binding.NativeDeniedReaders) > MaxLifecycleConsumers {
		return false
	}
	positive := make(map[string]bool, len(binding.ConsumerIDs))
	positiveUID := make(map[uint32]bool, len(binding.ConsumerIDs))
	positiveUnits := make(map[struct{ host, unit string }]bool, len(binding.ConsumerIDs))
	for _, id := range binding.ConsumerIDs {
		positive[id] = true
	}
	host := ""
	for _, item := range binding.NativeConsumers {
		if !positive[item.ConsumerID] || item.TargetID != binding.TargetID || !nativeMachineID.MatchString(item.HostMachineID) || !nativeUnitName.MatchString(item.UnitName) || strings.Contains(item.UnitName, "..") || item.ServiceUID == 0 || item.ServiceGID == 0 || item.LoadedName != LoadedNameForVersion(binding.NativeArtifactConsumerID, binding.ReferenceID, binding.MaterialVersion) {
			return false
		}
		if _, err := ParseID(item.ProfileID); err != nil {
			return false
		}
		if _, err := ParseID(item.RoleID); err != nil {
			return false
		}
		if host != "" && host != item.HostMachineID {
			return false
		}
		unitKey := struct{ host, unit string }{item.HostMachineID, item.UnitName}
		if positiveUnits[unitKey] {
			return false
		}
		positiveUnits[unitKey] = true
		host = item.HostMachineID
		delete(positive, item.ConsumerID)
		positiveUID[item.ServiceUID] = true
	}
	if len(positive) != 0 {
		return false
	}
	denied := make(map[string]bool, len(binding.RequiredDeniedConsumerIDs))
	deniedReaders := make(map[struct {
		host     string
		uid, gid uint32
	}]bool, len(binding.RequiredDeniedConsumerIDs))
	for _, id := range binding.RequiredDeniedConsumerIDs {
		denied[id] = true
	}
	for _, item := range binding.NativeDeniedReaders {
		if !denied[item.ConsumerID] || item.TargetID != binding.TargetID || item.HostMachineID != host || item.ReaderUID == 0 || item.ReaderGID == 0 || positiveUID[item.ReaderUID] {
			return false
		}
		if _, err := ParseID(item.ProfileID); err != nil {
			return false
		}
		if _, err := ParseID(item.RoleID); err != nil {
			return false
		}
		readerKey := struct {
			host     string
			uid, gid uint32
		}{item.HostMachineID, item.ReaderUID, item.ReaderGID}
		if deniedReaders[readerKey] {
			return false
		}
		deniedReaders[readerKey] = true
		delete(denied, item.ConsumerID)
	}
	return len(denied) == 0
}

func canonicalNativeConsumers(values []NativeConsumerBinding) string {
	items := make([]string, 0, len(values))
	for _, item := range values {
		items = append(items, strings.Join([]string{item.ConsumerID, item.TargetID, item.HostMachineID, item.UnitName, strconv.FormatUint(uint64(item.ServiceUID), 10), strconv.FormatUint(uint64(item.ServiceGID), 10), item.ProfileID, item.RoleID, item.LoadedName}, "\x00"))
	}
	slices.Sort(items)
	return strings.Join(items, "\x01")
}

func canonicalNativeDeniedReaders(values []NativeDeniedReaderBinding) string {
	items := make([]string, 0, len(values))
	for _, item := range values {
		items = append(items, strings.Join([]string{item.ConsumerID, item.TargetID, item.HostMachineID, strconv.FormatUint(uint64(item.ReaderUID), 10), strconv.FormatUint(uint64(item.ReaderGID), 10), item.ProfileID, item.RoleID}, "\x00"))
	}
	slices.Sort(items)
	return strings.Join(items, "\x01")
}
