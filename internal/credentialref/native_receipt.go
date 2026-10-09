package credentialref

import (
	"bytes"
	"encoding/json"
	"regexp"
)

// NativeInvocationMetadata contains file/process identities only. SourceFingerprint
// identifies encrypted bytes; no plaintext or plaintext hash is stored.
type NativeInvocationMetadata struct {
	BootID, InvocationID                               string
	MainPID                                            uint32
	ProcessStartTicks, NamespaceDevice, NamespaceInode uint64
	CredentialDevice, CredentialInode                  uint64
	CredentialUID, CredentialGID, CredentialMode       uint32
	SourceDevice, SourceInode                          uint64
	SourceFingerprint                                  string
}

// NativeLoadedReceipt preserves the actual lifecycle observation so later
// credential reads can check the same invocation without restarting a service.
type NativeLoadedReceipt struct {
	Version                               int
	Binding                               LifecycleBinding
	ConsumerID, PlanDigest, RunID, StepID string
	Proof                                 NativeInvocationMetadata
}

const MaxNativeLoadedReceiptBytes = 262144

var nativeReceiptBoot = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func (r NativeLoadedReceipt) Reader() (NativeConsumerBinding, bool) {
	for _, reader := range r.Binding.NativeConsumers {
		if reader.ConsumerID == r.ConsumerID {
			return reader, true
		}
	}
	return NativeConsumerBinding{}, false
}
func ValidNativeLoadedReceipt(r NativeLoadedReceipt) bool {
	if r.Version != 1 || !ValidLifecycleBinding(r.Binding) || r.Binding.ResolverID != "native-systemd" || !ValidSHA256Digest(r.PlanDigest) {
		return false
	}
	for _, id := range []string{r.RunID, r.StepID, r.ConsumerID} {
		if _, err := ParseID(id); err != nil {
			return false
		}
	}
	reader, ok := r.Reader()
	p := r.Proof
	return ok && nativeReceiptBoot.MatchString(p.BootID) && nativeMachineID.MatchString(p.InvocationID) && p.MainPID > 1 && p.MainPID <= 0x7fffffff && p.ProcessStartTicks != 0 && p.NamespaceDevice != 0 && p.NamespaceInode != 0 && p.CredentialDevice != 0 && p.CredentialInode != 0 && (p.CredentialUID == 0 || p.CredentialUID == reader.ServiceUID) && (p.CredentialGID == 0 || p.CredentialGID == reader.ServiceGID) && p.CredentialMode&0170000 == 0100000 && p.CredentialMode&0022 == 0 && p.SourceDevice != 0 && p.SourceInode != 0 && p.SourceFingerprint == r.Binding.CiphertextFingerprint
}
func EncodeNativeLoadedReceipt(r NativeLoadedReceipt) ([]byte, error) {
	if !ValidNativeLoadedReceipt(r) {
		return nil, newError("INPUT_INVALID", "native-loaded-receipt")
	}
	raw, err := json.Marshal(r)
	if err != nil || len(raw) > MaxNativeLoadedReceiptBytes {
		return nil, newError("INPUT_INVALID", "native-loaded-receipt")
	}
	return raw, nil
}
func DecodeNativeLoadedReceipt(raw []byte) (NativeLoadedReceipt, error) {
	var r NativeLoadedReceipt
	if len(raw) == 0 || len(raw) > MaxNativeLoadedReceiptBytes || json.Unmarshal(raw, &r) != nil {
		return r, newError("INPUT_INVALID", "native-loaded-receipt")
	}
	canonical, err := EncodeNativeLoadedReceipt(r)
	if err != nil || !bytes.Equal(raw, canonical) {
		return NativeLoadedReceipt{}, newError("INPUT_INVALID", "native-loaded-receipt")
	}
	return r, nil
}
