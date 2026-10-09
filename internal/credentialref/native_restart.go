package credentialref

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// NativeRestartContinuation is server-observed metadata sealed into a fresh
// human-acknowledged plan. It grants no restart or automatic recovery authority.
type NativeRestartContinuation struct {
	PriorRunID    string                   `json:"prior_run_id"`
	PriorStepID   string                   `json:"prior_step_id"`
	PendingDigest string                   `json:"pending_digest"`
	Expected      NativeInvocationMetadata `json:"expected"`
}
type NativeRestartBefore struct {
	ConsumerID, MachineID, BootID, InvocationID  string
	MainPID                                      uint32
	ProcessStartTicks, SourceDevice, SourceInode uint64
	SourceFingerprint                            string
	RequestMonotonicNanos                        int64
}
type NativeRestartPending struct {
	Version                                    int
	PlanID, PlanDigest, RunID, StepID, LeaseID string
	Binding                                    LifecycleBinding
	Before                                     NativeRestartBefore
}

func ValidNativeRestartContinuation(c *NativeRestartContinuation) bool {
	if c == nil || !ValidSHA256Digest(c.PendingDigest) {
		return false
	}
	for _, id := range []string{c.PriorRunID, c.PriorStepID} {
		if _, err := ParseID(id); err != nil {
			return false
		}
	}
	p := c.Expected
	return nativeReceiptBoot.MatchString(p.BootID) && nativeMachineID.MatchString(p.InvocationID) && p.MainPID > 1 && p.MainPID <= 0x7fffffff && p.ProcessStartTicks > 0 && p.NamespaceDevice > 0 && p.NamespaceInode > 0 && p.CredentialDevice > 0 && p.CredentialInode > 0 && p.CredentialMode&0170000 == 0100000 && p.CredentialMode&0022 == 0 && p.SourceDevice > 0 && p.SourceInode > 0 && ValidSHA256Digest(p.SourceFingerprint)
}
func NativeRestartContinuationDigest(c NativeRestartContinuation) string {
	raw, _ := json.Marshal(c)
	sum := sha256.Sum256(append([]byte("native-restart-continuation-v1\x00"), raw...))
	return "sha256:" + hex.EncodeToString(sum[:])
}
func ValidNativeRestartPending(p NativeRestartPending) bool {
	b := p.Binding
	if p.Version != 1 || !ValidLifecycleBinding(b) || b.NativeRestartContinuation != nil || b.HostActionConsole == nil || b.ResolverID != "native-systemd" || (b.Action != ActionActivate && b.Action != ActionRotate) || len(b.NativeConsumers) != 1 || !ValidSHA256Digest(p.PlanDigest) {
		return false
	}
	for _, id := range []string{p.PlanID, p.RunID, p.StepID, p.LeaseID} {
		if _, err := ParseID(id); err != nil {
			return false
		}
	}
	r := b.NativeConsumers[0]
	v := p.Before
	return v.ConsumerID == r.ConsumerID && v.MachineID == r.HostMachineID && nativeReceiptBoot.MatchString(v.BootID) && nativeMachineID.MatchString(v.InvocationID) && v.MainPID > 1 && v.MainPID <= 0x7fffffff && v.ProcessStartTicks > 0 && v.SourceDevice > 0 && v.SourceInode > 0 && v.SourceFingerprint == b.CiphertextFingerprint && v.RequestMonotonicNanos > 0
}
func EncodeNativeRestartPending(p NativeRestartPending) ([]byte, error) {
	if !ValidNativeRestartPending(p) {
		return nil, newError("INPUT_INVALID", "native-restart-pending")
	}
	raw, err := json.Marshal(p)
	if err != nil || len(raw) > MaxNativeLoadedReceiptBytes {
		return nil, newError("INPUT_INVALID", "native-restart-pending")
	}
	return raw, nil
}
func DecodeNativeRestartPending(raw []byte) (NativeRestartPending, error) {
	var p NativeRestartPending
	if len(raw) == 0 || len(raw) > MaxNativeLoadedReceiptBytes || json.Unmarshal(raw, &p) != nil {
		return p, newError("INPUT_INVALID", "native-restart-pending")
	}
	encoded, err := EncodeNativeRestartPending(p)
	if err != nil || !bytes.Equal(raw, encoded) {
		return NativeRestartPending{}, newError("INPUT_INVALID", "native-restart-pending")
	}
	return p, nil
}
func NativeRestartPendingDigest(p NativeRestartPending) string {
	raw, _ := json.Marshal(p)
	sum := sha256.Sum256(append([]byte("native-restart-pending-v1\x00"), raw...))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// MatchesNativeRestart binds a fresh plan to exactly the original attempted
// lifecycle, allowing only its new operation/state and explicit continuation.
func matchesNativeRestart(b LifecycleBinding, p NativeRestartPending) bool {
	c := b.NativeRestartContinuation
	if !ValidNativeRestartPending(p) || !ValidNativeRestartContinuation(c) || c.PriorRunID != p.RunID || c.PriorStepID != p.StepID || c.PendingDigest != NativeRestartPendingDigest(p) {
		return false
	}
	original := p.Binding
	b.NativeRestartContinuation = nil
	b.OperationID = original.OperationID
	b.StateRevision = original.StateRevision
	// Re-staging the same imported draft may use the current revision. Its exact
	// identity/material and all consumer/console bindings remain unchanged.
	b.ImportDraftStateRevision = original.ImportDraftStateRevision
	raw, _ := json.Marshal(b)
	prior, _ := json.Marshal(original)
	return bytes.Equal(raw, prior) && c.Expected.BootID == p.Before.BootID && c.Expected.InvocationID != p.Before.InvocationID && c.Expected.SourceDevice == p.Before.SourceDevice && c.Expected.SourceInode == p.Before.SourceInode && c.Expected.SourceFingerprint == p.Before.SourceFingerprint
}

func PendingMatchesLifecycle(p NativeRestartPending, b LifecycleBinding) bool {
	return matchesNativeRestart(b, p)
}
