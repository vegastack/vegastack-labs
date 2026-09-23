//go:build linux

package nativecredential

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
)

var errNativeLifecycle = errors.New("native credential lifecycle verification unavailable")

// NativeLifecycleVerifier owns only local, metadata-only evidence. Construction
// does not grant production authority; Verify requalifies the installed OS
// policy against the plan-sealed map before and after every effect.
type NativeLifecycleVerifier struct {
	Authority          NativeAuthority
	Units              AppliedUnitReader
	CiphertextRoot     string
	CiphertextOwnerUID uint32
	policy             func(credentialref.LifecycleBinding) error
	observe            func(context.Context, credentialref.LifecycleBinding, credentialref.NativeConsumerBinding) (NativeInvocationProof, error)
	recheck            func(context.Context, credentialref.LifecycleBinding, credentialref.NativeConsumerBinding, NativeInvocationProof) error
}

// NativeVerificationStep carries only immutable public plan identifiers. The
// server translates its run-engine binding into this narrow adapter input.
type NativeVerificationStep struct {
	OperationID, OperationType, TargetID, ArtifactDigest string
	PlanDigest, RunID, StepID                            string
}

func NewNativeLifecycleVerifier(authority *LocalNativeAuthority, units AppliedUnitReader, ciphertextRoot string, ownerUID uint32) (*NativeLifecycleVerifier, error) {
	if authority == nil || units == nil || !filepath.IsAbs(ciphertextRoot) || filepath.Clean(ciphertextRoot) != ciphertextRoot {
		return nil, errNativeLifecycle
	}
	v := &NativeLifecycleVerifier{Authority: authority, Units: units, CiphertextRoot: ciphertextRoot, CiphertextOwnerUID: ownerUID,
		policy: qualifyNativePolicy}
	observer := invocationObserver{units: units, authority: authority, root: ciphertextRoot, ownerUID: ownerUID,
		inspect: InspectEncrypted, process: observeProcessIdentity}
	v.observe = observer.observe
	v.recheck = v.recheckProof
	return v, nil
}

// NewInstalledNativeLifecycleVerifier is the only production constructor. An
// absent or drifting root-owned OS enrollment leaves the server on its
// unavailable sentinel; the sealed binding is checked again at Verify time.
func NewInstalledNativeLifecycleVerifier(ctx context.Context, ciphertextRoot string, ownerUID uint32) (*NativeLifecycleVerifier, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, errNativeLifecycle
	}
	root, err := os.Lstat(ciphertextRoot)
	if err != nil || !root.IsDir() || root.Mode().Perm() != 0o700 {
		return nil, errNativeLifecycle
	}
	rootStat, ok := root.Sys().(*syscall.Stat_t)
	if !ok || rootStat.Uid != ownerUID {
		return nil, errNativeLifecycle
	}
	policy, err := readProbePolicy(probePolicyPath)
	if err != nil {
		return nil, errNativeLifecycle
	}
	machine, err := os.ReadFile("/etc/machine-id")
	if err != nil || strings.TrimSpace(string(machine)) != policy.MachineID {
		return nil, errNativeLifecycle
	}
	authority, err := NewNativeAuthority(policy.Units)
	if err != nil {
		return nil, errNativeLifecycle
	}
	for _, unit := range policy.Units {
		if !authority.qualified(ctx, unit) {
			return nil, errNativeLifecycle
		}
	}
	return NewNativeLifecycleVerifier(authority, SystemdUnitReader{}, ciphertextRoot, ownerUID)
}

func (v *NativeLifecycleVerifier) VerifyNative(ctx context.Context, step NativeVerificationStep, binding credentialref.LifecycleBinding) ([]credentialref.ConsumerVerification, error) {
	if ctx == nil || ctx.Err() != nil || v == nil || v.Authority == nil || v.policy == nil || v.observe == nil || v.recheck == nil ||
		!credentialref.ValidLifecycleBinding(binding) || binding.ResolverID != "native-systemd" ||
		step.OperationID != binding.OperationID || step.OperationType != string(binding.Action) ||
		step.TargetID != binding.TargetID || step.ArtifactDigest != binding.CiphertextFingerprint || v.policy(binding) != nil {
		return nil, errNativeLifecycle
	}
	positive := append([]credentialref.NativeConsumerBinding(nil), binding.NativeConsumers...)
	slices.SortFunc(positive, func(a, b credentialref.NativeConsumerBinding) int { return strings.Compare(a.ConsumerID, b.ConsumerID) })
	proofs := make(map[string]NativeInvocationProof, len(positive))
	results := make([]credentialref.ConsumerVerification, 0, len(positive)+len(binding.NativeDeniedReaders))
	for _, reader := range positive {
		proof, err := v.observe(ctx, binding, reader)
		if err != nil || !validNativeProof(proof, reader, binding) {
			return nil, errNativeLifecycle
		}
		proofs[reader.ConsumerID] = proof
		evidence := nativeEvidenceDigest("positive", binding.Digest(), step.PlanDigest, step.RunID, step.StepID,
			reader.ConsumerID, reader.ProfileID, reader.RoleID, reader.UnitName, proof.BootID, proof.InvocationID,
			strconv.FormatUint(uint64(proof.MainPID), 10), strconv.FormatUint(proof.ProcessStartTicks, 10),
			strconv.FormatUint(proof.NamespaceDevice, 10), strconv.FormatUint(proof.NamespaceInode, 10),
			strconv.FormatUint(proof.CredentialDevice, 10), strconv.FormatUint(proof.CredentialInode, 10),
			strconv.FormatUint(proof.SourceDevice, 10), strconv.FormatUint(proof.SourceInode, 10), proof.SourceFingerprint)
		verification, err := credentialref.NewConsumerVerification(binding, reader.ConsumerID, reader.ProfileID, reader.RoleID, evidence, "native-systemd-delivery", "verified", true)
		if err != nil {
			return nil, errNativeLifecycle
		}
		results = append(results, verification)
	}
	denied := append([]credentialref.NativeDeniedReaderBinding(nil), binding.NativeDeniedReaders...)
	slices.SortFunc(denied, func(a, b credentialref.NativeDeniedReaderBinding) int {
		return strings.Compare(a.ConsumerID, b.ConsumerID)
	})
	for _, reader := range denied {
		parts := []string{"denied", binding.Digest(), step.PlanDigest, step.RunID, step.StepID,
			reader.ConsumerID, reader.ProfileID, reader.RoleID, strconv.FormatUint(uint64(reader.ReaderUID), 10), strconv.FormatUint(uint64(reader.ReaderGID), 10)}
		for _, target := range positive {
			proof := proofs[target.ConsumerID]
			request := AccessProbeRequest{UID: reader.ReaderUID, GID: reader.ReaderGID, UnitName: target.UnitName, CredentialName: target.LoadedName,
				MainPID: int(proof.MainPID), ProcessStartTicks: proof.ProcessStartTicks, BootID: proof.BootID}
			result, err := v.Authority.Probe(ctx, request)
			if err != nil || !validProbeResult(result) || result.Status != AccessProbeDenied || ctx.Err() != nil {
				return nil, errNativeLifecycle
			}
			parts = append(parts, target.UnitName, proof.InvocationID, strconv.FormatUint(proof.CredentialDevice, 10), strconv.FormatUint(proof.CredentialInode, 10), string(result.Status))
		}
		verification, err := credentialref.NewConsumerVerification(binding, reader.ConsumerID, reader.ProfileID, reader.RoleID,
			nativeEvidenceDigest(parts...), "native-direct-open-denied", "denied", false)
		if err != nil {
			return nil, errNativeLifecycle
		}
		results = append(results, verification)
	}
	for _, reader := range positive {
		if v.recheck(ctx, binding, reader, proofs[reader.ConsumerID]) != nil {
			return nil, errNativeLifecycle
		}
	}
	if ctx.Err() != nil || v.policy(binding) != nil {
		return nil, errNativeLifecycle
	}
	return results, nil
}

func validNativeProof(proof NativeInvocationProof, reader credentialref.NativeConsumerBinding, binding credentialref.LifecycleBinding) bool {
	return bootIDPattern.MatchString(proof.BootID) && len(proof.InvocationID) == 32 && proof.MainPID > 1 && proof.ProcessStartTicks != 0 &&
		proof.NamespaceInode != 0 && proof.CredentialDevice != 0 && proof.CredentialInode != 0 && (proof.CredentialUID == 0 || proof.CredentialUID == reader.ServiceUID) &&
		(proof.CredentialGID == 0 || proof.CredentialGID == reader.ServiceGID) && proof.CredentialMode&unix.S_IFMT == unix.S_IFREG && proof.CredentialMode&0o022 == 0 &&
		proof.SourceDevice != 0 && proof.SourceInode != 0 && proof.SourceFingerprint == binding.CiphertextFingerprint
}

func nativeEvidenceDigest(parts ...string) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte("native-lifecycle-evidence-v1\x00"))
	for _, part := range parts {
		_, _ = hash.Write([]byte(part))
		_, _ = hash.Write([]byte{0})
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}

func qualifyNativePolicy(binding credentialref.LifecycleBinding) error {
	policy, err := readProbePolicy(probePolicyPath)
	if err != nil {
		return errNativeLifecycle
	}
	return matchNativePolicy(policy, binding)
}

func matchNativePolicy(policy probePolicy, binding credentialref.LifecycleBinding) error {
	if !credentialref.ValidNativeBindings(binding) || len(binding.NativeConsumers) == 0 || policy.MachineID != binding.NativeConsumers[0].HostMachineID {
		return errNativeLifecycle
	}
	units := make([]string, 0, len(binding.NativeConsumers))
	probes := make([]probeEnrollment, 0, len(binding.NativeConsumers)*(len(binding.NativeDeniedReaders)+1))
	for _, positive := range binding.NativeConsumers {
		units = append(units, positive.UnitName)
		probes = append(probes, probeEnrollment{UnitName: positive.UnitName, CredentialName: positive.LoadedName, UID: positive.ServiceUID, GID: positive.ServiceGID})
		for _, denied := range binding.NativeDeniedReaders {
			probes = append(probes, probeEnrollment{UnitName: positive.UnitName, CredentialName: positive.LoadedName, UID: denied.ReaderUID, GID: denied.ReaderGID})
		}
	}
	slices.Sort(units)
	for index := 1; index < len(units); index++ {
		if units[index] == units[index-1] {
			return errNativeLifecycle
		}
	}
	slices.SortFunc(probes, func(a, b probeEnrollment) int { return strings.Compare(probeEnrollmentKey(a), probeEnrollmentKey(b)) })
	if !reflect.DeepEqual(units, policy.Units) || !reflect.DeepEqual(probes, policy.Probes) {
		return errNativeLifecycle
	}
	return nil
}

func probeEnrollmentKey(p probeEnrollment) string {
	return fmt.Sprintf("%s\x00%s\x00%010d\x00%010d", p.UnitName, p.CredentialName, p.UID, p.GID)
}

func (v *NativeLifecycleVerifier) recheckProof(ctx context.Context, binding credentialref.LifecycleBinding, reader credentialref.NativeConsumerBinding, proof NativeInvocationProof) error {
	if v == nil || v.Units == nil || ctx == nil || ctx.Err() != nil {
		return errNativeLifecycle
	}
	snapshot, err := v.Units.ObserveAppliedUnit(ctx, reader.UnitName)
	path := filepath.Join(v.CiphertextRoot, reader.LoadedName)
	if err != nil || validateAppliedSource(snapshot, binding, reader, path) != nil || snapshot.MachineID != reader.HostMachineID ||
		snapshot.BootID != proof.BootID || snapshot.InvocationID != proof.InvocationID || snapshot.MainPID != proof.MainPID || !unitIdentityMatches(snapshot, reader) {
		return errNativeLifecycle
	}
	process, err := observeProcessIdentity(ctx, snapshot, reader)
	if err != nil || process.StartTicks != proof.ProcessStartTicks {
		return errNativeLifecycle
	}
	request := AccessProbeRequest{UID: reader.ServiceUID, GID: reader.ServiceGID, UnitName: reader.UnitName, CredentialName: reader.LoadedName,
		MainPID: int(proof.MainPID), ProcessStartTicks: proof.ProcessStartTicks, BootID: proof.BootID}
	loaded, err := v.Authority.Probe(ctx, request)
	if err != nil || loaded.Status != AccessProbeOpened || loaded.NamespaceDevice != proof.NamespaceDevice || loaded.NamespaceInode != proof.NamespaceInode || loaded.Device != proof.CredentialDevice || loaded.Inode != proof.CredentialInode ||
		loaded.OwnerUID != proof.CredentialUID || loaded.OwnerGID != proof.CredentialGID || loaded.Mode != proof.CredentialMode {
		return errNativeLifecycle
	}
	source, err := InspectEncrypted(ctx, InspectRequest{Name: reader.LoadedName, CiphertextDirectory: v.CiphertextRoot, ExpectedUID: v.CiphertextOwnerUID})
	if err != nil || source.State != "present" || source.Fingerprint != proof.SourceFingerprint || source.Device != proof.SourceDevice || source.Inode != proof.SourceInode || ctx.Err() != nil {
		return errNativeLifecycle
	}
	return nil
}
