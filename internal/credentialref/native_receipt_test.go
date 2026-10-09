package credentialref

import (
	"strings"
	"testing"
)

func nativeReceiptFixture() NativeLoadedReceipt {
	b := validActivateBinding()
	return NativeLoadedReceipt{Version: 1, Binding: b, ConsumerID: b.ConsumerIDs[0], PlanDigest: "sha256:" + strings.Repeat("a", 64), RunID: "run-a", StepID: "step-a", Proof: NativeInvocationMetadata{BootID: "00000000-0000-0000-0000-000000000001", InvocationID: strings.Repeat("b", 32), MainPID: 42, ProcessStartTicks: 1, NamespaceDevice: 1, NamespaceInode: 2, CredentialDevice: 3, CredentialInode: 4, CredentialUID: 1001, CredentialGID: 1001, CredentialMode: 0100400, SourceDevice: 5, SourceInode: 6, SourceFingerprint: b.CiphertextFingerprint}}
}
func TestNativeLoadedReceiptPreservesExactInvocation(t *testing.T) {
	r := nativeReceiptFixture()
	raw, err := EncodeNativeLoadedReceipt(r)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeNativeLoadedReceipt(raw)
	if err != nil || got.Proof != r.Proof {
		t.Fatal("receipt lost invocation", err)
	}
	for name, mutate := range map[string]func(*NativeLoadedReceipt){
		"boot":       func(r *NativeLoadedReceipt) { r.Proof.BootID = "current" },
		"invocation": func(r *NativeLoadedReceipt) { r.Proof.InvocationID = strings.Repeat("z", 32) },
		"process":    func(r *NativeLoadedReceipt) { r.Proof.ProcessStartTicks = 0 },
		"source":     func(r *NativeLoadedReceipt) { r.Proof.SourceFingerprint = "sha256:" + strings.Repeat("f", 64) },
		"inode":      func(r *NativeLoadedReceipt) { r.Proof.CredentialInode = 0 },
		"mode":       func(r *NativeLoadedReceipt) { r.Proof.CredentialMode = 0100666 },
		"consumer":   func(r *NativeLoadedReceipt) { r.ConsumerID = "other" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := r
			mutate(&changed)
			if _, err := EncodeNativeLoadedReceipt(changed); err == nil {
				t.Fatal("invalid receipt accepted")
			}
		})
	}
	if _, err := DecodeNativeLoadedReceipt(append(raw, []byte(`{}`)...)); err == nil {
		t.Fatal("trailing data accepted")
	}
	if _, err := DecodeNativeLoadedReceipt([]byte(`{"Version":1,"Version":1}`)); err == nil {
		t.Fatal("noncanonical duplicate accepted")
	}
}
