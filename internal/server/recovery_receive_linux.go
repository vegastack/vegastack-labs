//go:build linux

package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/hostadoption"
	"github.com/vegastack/vegastack-labs/internal/hostreplacement"
	"github.com/vegastack/vegastack-labs/internal/linuxrole"
	"github.com/vegastack/vegastack-labs/internal/recovery"
	"github.com/vegastack/vegastack-labs/internal/store"
	"golang.org/x/sys/unix"
)

const RecoveryReceiveMode = "server-recovery-receive-once"
const receiveDatabase = "/var/lib/vsk-labs/control/control.db"
const receiveSeals = unix.F_SEAL_SEAL | unix.F_SEAL_SHRINK | unix.F_SEAL_GROW | unix.F_SEAL_WRITE

type recoveryReceiveHandler struct{ version string }

func RecoveryReceiveDispatcher(version string) hostaction.Dispatcher {
	return recoveryReceiveDispatcher{version}
}

type recoveryReceiveDispatcher struct{ version string }

func (d recoveryReceiveDispatcher) Lookup(id, version string) (hostaction.Handler, bool) {
	if id != hostaction.RecoveryReceiveAction || version != "1.0.0" {
		return nil, false
	}
	return recoveryReceiveHandler{d.version}, true
}
func (h recoveryReceiveHandler) Execute(context.Context, generated.HostActionBundle) (generated.HostActionResult, error) {
	return generated.HostActionResult{}, errRecoveryReceive()
}
func (h recoveryReceiveHandler) Verify(_ context.Context, b generated.HostActionBundle, r generated.HostActionResult) error {
	digest, err := hostaction.BundleDigest(b)
	if err != nil || r.BundleDigest != digest || r.Status != "succeeded" || !r.Changed || !r.EffectObserved || r.Reason != "verified" || r.ResultDigest != hostaction.ResultDigest(r) {
		return errRecoveryReceive()
	}
	return nil
}
func errRecoveryReceive() error { return fmt.Errorf("recovery receive unavailable") }

type recoveryReceiveAttestation struct {
	Descriptor       generated.ControlRecoveryReceiveInput `json:"descriptor"`
	Bundle           generated.HostActionBundle            `json:"bundle"`
	ParentPID        int                                   `json:"parentPid"`
	ParentStart      uint64                                `json:"parentStart"`
	ExecutableDigest string                                `json:"executableDigest"`
	ObservedAt       string                                `json:"observedAt"`
}
type recoveryReceiveConfirmation struct {
	DescriptorDigest string `json:"descriptorDigest"`
	InstanceID       string `json:"instanceId"`
	RecoveryEpoch    int64  `json:"recoveryEpoch"`
}

func decodeReceiveInput(b generated.HostActionBundle) (generated.ControlRecoveryReceiveInput, error) {
	var d generated.ControlRecoveryReceiveInput
	raw := []byte(b.ActionInput)
	if b.ActionID != hostaction.RecoveryReceiveAction || b.ActionVersion != "1.0.0" || hostaction.BytesDigest(raw) != b.ActionInputDigest || generated.ValidateContractJSON(generated.SchemaIDControlRecoveryReceiveInput, raw, generated.ContractExact) != nil || json.Unmarshal(raw, &d) != nil || recovery.ValidateCandidateTransferDescriptor(d) != nil || d.Replacement.NewHostID != b.HostID || d.Replacement.NewIdentityDigest != b.HostIdentityDigest || d.RoleInput.HostID != b.HostID || d.RoleInput.HostIdentityDigest != b.HostIdentityDigest || d.RoleInput.AutomationUID != b.CallerUID {
		return d, errRecoveryReceive()
	}
	return d, nil
}
func inspectReceiveDestination(ctx context.Context, b generated.HostActionBundle, d generated.ControlRecoveryReceiveInput, version string) error {
	if os.Getuid() != 0 || os.Geteuid() != 0 || d.RoleInput.ProfileLock.ExecutableVersion != version || linuxrole.InspectNativeRecoveryDestination(ctx, b, d.RoleInput, d.ServiceUID, d.ServiceGID) != nil {
		return errRecoveryReceive()
	}
	p := "/sys/class/dmi/id/product_serial"
	if d.DestinationIdentityKind == "product-uuid" {
		p = "/sys/class/dmi/id/product_uuid"
	}
	raw, err := os.ReadFile(p)
	if err != nil || len(raw) > 4096 || hostadoption.IdentityDigest(d.DestinationIdentityKind, strings.TrimSpace(string(raw))) != d.Replacement.NewIdentityDigest {
		return errRecoveryReceive()
	}
	raw, err = os.ReadFile("/etc/ssh/ssh_host_ed25519_key.pub")
	if err != nil || len(raw) > 16384 {
		return errRecoveryReceive()
	}
	key, err := hostreplacement.SSHHostKeyDigest(string(raw))
	if err != nil || key != d.Replacement.NewSSHHostKeyDigest {
		return errRecoveryReceive()
	}
	return receiveCapacity(d)
}
func receiveCapacity(d generated.ControlRecoveryReceiveInput) error {
	var st unix.Statfs_t
	if unix.Statfs("/var/lib/vsk-labs/control", &st) != nil || st.Bsize <= 0 || st.Bavail > uint64(^uint64(0))/uint64(st.Bsize) || st.Bavail*uint64(st.Bsize) < uint64(d.CandidateBytes)*2+64<<20 {
		return errRecoveryReceive()
	}
	return nil
}
func newReceiveMemfd(name string) (*os.File, error) {
	fd, err := unix.MemfdCreate(name, unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, errRecoveryReceive()
	}
	return os.NewFile(uintptr(fd), name), nil
}
func sealReceiveFile(f *os.File) error {
	if _, err := unix.FcntlInt(f.Fd(), unix.F_ADD_SEALS, receiveSeals); err != nil {
		return errRecoveryReceive()
	}
	_, err := f.Seek(0, io.SeekStart)
	return err
}
func (h recoveryReceiveHandler) ExecuteRecoveryPayload(ctx context.Context, b generated.HostActionBundle, input io.Reader) (generated.HostActionResult, error) {
	fail := func() (generated.HostActionResult, error) { return generated.HostActionResult{}, errRecoveryReceive() }
	d, err := decodeReceiveInput(b)
	if err != nil || inspectReceiveDestination(ctx, b, d, h.version) != nil {
		return fail()
	}
	candidate, err := newReceiveMemfd("vsk-recovery-candidate")
	if err != nil {
		return fail()
	}
	defer candidate.Close()
	journal, err := newReceiveMemfd("vsk-recovery-journal")
	if err != nil {
		return fail()
	}
	defer journal.Close()
	if hostaction.CopyRecoveryPayload(ctx, candidate, input, d.CandidateBytes, hostaction.MaximumRecoveryCandidateBytes, d.CandidateBytesDigest) != nil || hostaction.CopyRecoveryPayload(ctx, journal, input, d.JournalBytes, hostaction.MaximumRecoveryJournalBytes, d.JournalDigest) != nil {
		return fail()
	}
	var tail [1]byte
	if n, e := input.Read(tail[:]); n != 0 || e != io.EOF || ctx.Err() != nil {
		return fail()
	}
	if sealReceiveFile(candidate) != nil || sealReceiveFile(journal) != nil || inspectReceiveDestination(ctx, b, d, h.version) != nil {
		return fail()
	}
	executable, err := os.Open("/proc/self/exe")
	if err != nil {
		return fail()
	}
	defer executable.Close()
	executableDigest, err := receiveExecutableDigest(executable)
	if err != nil || executableDigest != d.RoleInput.ExecutableDigest {
		return fail()
	}
	start, err := receiveProcessStart(os.Getpid())
	if err != nil {
		return fail()
	}
	attestation := recoveryReceiveAttestation{d, b, os.Getpid(), start, executableDigest, time.Now().UTC().Format(time.RFC3339Nano)}
	raw, err := json.Marshal(attestation)
	if err != nil || len(raw) > 256<<10 {
		return fail()
	}
	sealed, err := newReceiveMemfd("vsk-recovery-attestation")
	if err != nil {
		return fail()
	}
	defer sealed.Close()
	if n, e := sealed.Write(raw); e != nil || n != len(raw) || sealReceiveFile(sealed) != nil {
		return fail()
	}
	command := exec.CommandContext(ctx, "/proc/self/exe", RecoveryReceiveMode)
	command.Dir = "/"
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	command.ExtraFiles = []*os.File{sealed, candidate, journal, executable}
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(d.ServiceUID), Gid: uint32(d.ServiceGID), Groups: []uint32{}}, Pdeathsig: syscall.SIGKILL}
	var output receiveBoundedOutput
	command.Stdout = &output
	command.Stderr = io.Discard
	if command.Run() != nil {
		return fail()
	}
	var confirmation recoveryReceiveConfirmation
	if json.Unmarshal(output.Bytes(), &confirmation) != nil || confirmation.DescriptorDigest != hostaction.Digest(d) || confirmation.InstanceID != d.Binding.NewInstanceID || confirmation.RecoveryEpoch != d.Binding.NextRecoveryEpoch {
		return fail()
	}
	bundleDigest, _ := hostaction.BundleDigest(b)
	result := generated.HostActionResult{Schema: generated.SchemaIDHostActionResult, SchemaVersion: "1.0.0", BundleDigest: bundleDigest, Status: "succeeded", Changed: true, EffectObserved: true, Reason: "verified"}
	result.ResultDigest = hostaction.ResultDigest(result)
	return result, nil
}

type receiveBoundedOutput struct{ bytes.Buffer }

func (b *receiveBoundedOutput) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 4096 {
		return 0, errRecoveryReceive()
	}
	return b.Buffer.Write(p)
}
func receiveExecutableDigest(f *os.File) (string, error) {
	var st unix.Stat_t
	if unix.Fstat(int(f.Fd()), &st) != nil || st.Uid != 0 || st.Mode&(0022|unix.S_ISUID|unix.S_ISGID) != 0 || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Size <= 0 || st.Size > 256<<20 {
		return "", errRecoveryReceive()
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return "", errRecoveryReceive()
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, st.Size+1))
	if err != nil || n != st.Size {
		return "", errRecoveryReceive()
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}
func receiveProcessStart(pid int) (uint64, error) {
	raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil || len(raw) > 16384 {
		return 0, errRecoveryReceive()
	}
	end := strings.LastIndexByte(string(raw), ')')
	if end < 0 {
		return 0, errRecoveryReceive()
	}
	fields := strings.Fields(string(raw[end+1:]))
	if len(fields) < 20 {
		return 0, errRecoveryReceive()
	}
	ticks, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || ticks == 0 {
		return 0, errRecoveryReceive()
	}
	return ticks, nil
}
func validateReceiveSealed(f *os.File, size, maximum int64) error {
	var st unix.Stat_t
	seals, err := unix.FcntlInt(f.Fd(), unix.F_GET_SEALS, 0)
	if err != nil || seals&receiveSeals != receiveSeals || unix.Fstat(int(f.Fd()), &st) != nil || st.Uid != 0 || st.Nlink != 0 || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Size <= 0 || st.Size > maximum || (size > 0 && st.Size != size) {
		return errRecoveryReceive()
	}
	return nil
}
func readReceiveAttestation(attestation, candidate, journal, executable *os.File) (recoveryReceiveAttestation, error) {
	var a recoveryReceiveAttestation
	if os.Getuid() == 0 || os.Getuid() != os.Geteuid() || os.Getgid() != os.Getegid() || validateReceiveSealed(attestation, 0, 256<<10) != nil {
		return a, errRecoveryReceive()
	}
	raw, err := io.ReadAll(io.LimitReader(attestation, (256<<10)+1))
	if err != nil || json.Unmarshal(raw, &a) != nil {
		return a, errRecoveryReceive()
	}
	canonical, err := json.Marshal(a)
	if err != nil || !bytes.Equal(raw, canonical) {
		return a, errRecoveryReceive()
	}
	d, err := decodeReceiveInput(a.Bundle)
	if err != nil || hostaction.Digest(d) != hostaction.Digest(a.Descriptor) || int64(os.Getuid()) != d.ServiceUID || int64(os.Getgid()) != d.ServiceGID || a.ParentPID != os.Getppid() {
		return a, errRecoveryReceive()
	}
	if validateReceiveProcess(a, candidate, journal, executable) != nil {
		return a, errRecoveryReceive()
	}
	return a, nil
}

type sealedReceiveDestination struct{ attestation recoveryReceiveAttestation }

func (s sealedReceiveDestination) VerifyCandidateTransferDestination(ctx context.Context, d recovery.CandidateTransferDescriptor) error {
	deadline, err := time.Parse(time.RFC3339, s.attestation.Bundle.ExpiresAt)
	if ctx.Err() != nil || err != nil || !deadline.After(time.Now()) || hostaction.Digest(d) != hostaction.Digest(s.attestation.Descriptor) || os.Getppid() != s.attestation.ParentPID {
		return errRecoveryReceive()
	}
	start, err := receiveProcessStart(s.attestation.ParentPID)
	if err != nil || start != s.attestation.ParentStart {
		return errRecoveryReceive()
	}
	if linuxrole.RecheckNativeRecoveryDestination(ctx, d.RoleInput, d.ServiceUID, d.ServiceGID) != nil {
		return errRecoveryReceive()
	}
	return receiveCapacity(d)
}

// RunRecoveryReceiveOnce owns the only SQLite access in the receive process.
// The fixed inherited descriptors come solely from the root launcher; no path,
// configuration, command or authority is accepted from argv or environment.
func RunRecoveryReceiveOnce(ctx context.Context, version string, output io.Writer) error {
	files := []*os.File{os.NewFile(3, "attestation"), os.NewFile(4, "candidate"), os.NewFile(5, "journal"), os.NewFile(6, "executable")}
	for _, f := range files {
		defer f.Close()
	}
	a, err := readReceiveAttestation(files[0], files[1], files[2], files[3])
	if err != nil {
		return errRecoveryReceive()
	}
	deadline, _ := time.Parse(time.RFC3339, a.Bundle.ExpiresAt)
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	d := a.Descriptor
	if d.RoleInput.ProfileLock.ExecutableVersion != version {
		return errRecoveryReceive()
	}
	opener := func(ctx context.Context, path string) (*store.Store, error) {
		return store.Open(ctx, store.Config{DatabasePath: path, Mode: store.OpenExisting, ExpectedUID: uint32(d.ServiceUID), ToolVersion: version, BuildVersion: a.ExecutableDigest})
	}
	receiver := recovery.CandidateTransferReceiver{DatabasePath: receiveDatabase, ExpectedUID: uint32(d.ServiceUID), Authority: recovery.StoreCandidateAuthority{Open: opener}, Bundles: recovery.StoreRecoveryBundleStore{Open: opener}, Destination: sealedReceiveDestination{a}}
	result, err := receiver.Receive(ctx, d, files[1], files[2])
	if err != nil || result.InstanceID != d.Binding.NewInstanceID || result.RecoveryEpoch != d.Binding.NextRecoveryEpoch {
		return errRecoveryReceive()
	}
	return json.NewEncoder(output).Encode(recoveryReceiveConfirmation{hostaction.Digest(d), result.InstanceID, result.RecoveryEpoch})
}

func validateReceiveProcess(a recoveryReceiveAttestation, candidate, journal, executable *os.File) error {
	if os.Getuid() == 0 || os.Getuid() != os.Geteuid() || os.Getgid() != os.Getegid() || a.ParentPID != os.Getppid() {
		return errRecoveryReceive()
	}
	var parent unix.Stat_t
	if unix.Stat("/proc/"+strconv.Itoa(a.ParentPID), &parent) != nil || parent.Uid != 0 {
		return errRecoveryReceive()
	}
	start, err := receiveProcessStart(a.ParentPID)
	if err != nil || start != a.ParentStart {
		return errRecoveryReceive()
	}
	observed, e := time.Parse(time.RFC3339Nano, a.ObservedAt)
	deadline, f := time.Parse(time.RFC3339, a.Bundle.ExpiresAt)
	now := time.Now()
	if e != nil || f != nil || observed.After(now) || now.Sub(observed) > 30*time.Second || !deadline.After(now) {
		return errRecoveryReceive()
	}
	self, err := os.Open("/proc/self/exe")
	if err != nil {
		return errRecoveryReceive()
	}
	defer self.Close()
	theirs, e := executable.Stat()
	ours, f := self.Stat()
	if e != nil || f != nil || !os.SameFile(theirs, ours) {
		return errRecoveryReceive()
	}
	digest, err := receiveExecutableDigest(executable)
	if err != nil || digest != a.ExecutableDigest || digest != a.Descriptor.RoleInput.ExecutableDigest || validateReceiveSealed(candidate, a.Descriptor.CandidateBytes, hostaction.MaximumRecoveryCandidateBytes) != nil || validateReceiveSealed(journal, a.Descriptor.JournalBytes, hostaction.MaximumRecoveryJournalBytes) != nil {
		return errRecoveryReceive()
	}
	return nil
}
