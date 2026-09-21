//go:build linux

package nativecredential

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
)

var errNativeInvocation = errors.New("native credential invocation unavailable")

type ProcessIdentity struct {
	MainPID         uint32
	StartTicks      uint64
	UID, GID        uint32
	NamespaceDevice uint64
	NamespaceInode  uint64
}

type NativeInvocationProof struct {
	BootID, InvocationID         string
	MainPID                      uint32
	ProcessStartTicks            uint64
	NamespaceDevice              uint64
	NamespaceInode               uint64
	CredentialDevice             uint64
	CredentialInode              uint64
	CredentialUID, CredentialGID uint32
	CredentialMode               uint32
	SourceDevice                 uint64
	SourceInode                  uint64
	SourceFingerprint            string
}

type invocationObserver struct {
	units     AppliedUnitReader
	authority NativeAuthority
	root      string
	ownerUID  uint32
	inspect   func(context.Context, InspectRequest) (CiphertextInspection, error)
	process   func(context.Context, AppliedUnitSnapshot, credentialref.NativeConsumerBinding) (ProcessIdentity, error)
}

func (o invocationObserver) observe(ctx context.Context, binding credentialref.LifecycleBinding, reader credentialref.NativeConsumerBinding) (NativeInvocationProof, error) {
	if ctx == nil || ctx.Err() != nil || o.units == nil || o.authority == nil || o.inspect == nil || o.process == nil ||
		!filepath.IsAbs(o.root) || filepath.Clean(o.root) != o.root || reader.HostMachineID == "" {
		return NativeInvocationProof{}, errNativeInvocation
	}
	path := filepath.Join(o.root, reader.LoadedName)
	first, err := o.units.ObserveAppliedUnit(ctx, reader.UnitName)
	if err != nil || first.MachineID != reader.HostMachineID || first.BootID == "" || first.UnitName != reader.UnitName ||
		first.NeedDaemonReload || first.EncryptedSources == nil || len(first.EncryptedSources) != 1 ||
		first.EncryptedSources[0].ID != reader.LoadedName || first.EncryptedSources[0].AbsolutePath != path {
		return NativeInvocationProof{}, errNativeInvocation
	}
	before, err := o.inspect(ctx, InspectRequest{Name: reader.LoadedName, CiphertextDirectory: o.root, ExpectedUID: o.ownerUID})
	if err != nil || before.State != "present" || before.Fingerprint != binding.CiphertextFingerprint || before.Device == 0 || before.Inode == 0 {
		return NativeInvocationProof{}, errNativeInvocation
	}
	receipt, err := o.authority.Restart(ctx, reader.UnitName)
	if err != nil || receipt.UnitName != reader.UnitName || receipt.BootID != first.BootID || receipt.Status != "completed" ||
		receipt.RequestMonotonicNanos <= 0 || receipt.FinishMonotonicNanos < receipt.RequestMonotonicNanos {
		return NativeInvocationProof{}, errNativeInvocation
	}
	after, err := o.units.ObserveAppliedUnit(ctx, reader.UnitName)
	if err != nil || validateAppliedSource(after, binding, reader, path) != nil || after.MachineID != first.MachineID || after.BootID != receipt.BootID ||
		after.InvocationID == first.InvocationID || after.InvocationID == "" || after.MainPID <= 1 ||
		after.ExecMainStartMonotonicUSec < uint64(receipt.RequestMonotonicNanos/1000) {
		return NativeInvocationProof{}, errNativeInvocation
	}
	if !unitIdentityMatches(after, reader) {
		return NativeInvocationProof{}, errNativeInvocation
	}
	process, err := o.process(ctx, after, reader)
	if err != nil || process.MainPID != after.MainPID || process.StartTicks == 0 || process.UID != reader.ServiceUID || process.GID != reader.ServiceGID || process.NamespaceInode == 0 {
		return NativeInvocationProof{}, errNativeInvocation
	}
	request := AccessProbeRequest{UID: reader.ServiceUID, GID: reader.ServiceGID, UnitName: reader.UnitName, CredentialName: reader.LoadedName,
		MainPID: int(after.MainPID), ProcessStartTicks: process.StartTicks, BootID: after.BootID}
	loaded, err := o.authority.Probe(ctx, request)
	if err != nil || !validProbeResult(loaded) || loaded.Status != AccessProbeOpened || loaded.OwnerUID != reader.ServiceUID || loaded.OwnerGID != reader.ServiceGID || loaded.Mode&unix.S_IFMT != unix.S_IFREG || loaded.Mode&0o077 != 0 {
		return NativeInvocationProof{}, errNativeInvocation
	}
	rechecked, err := o.units.ObserveAppliedUnit(ctx, reader.UnitName)
	if err != nil || !sameInvocation(after, rechecked) || validateAppliedSource(rechecked, binding, reader, path) != nil {
		return NativeInvocationProof{}, errNativeInvocation
	}
	processAgain, err := o.process(ctx, rechecked, reader)
	if err != nil || processAgain != process {
		return NativeInvocationProof{}, errNativeInvocation
	}
	loadedAgain, err := o.authority.Probe(ctx, request)
	if err != nil || loadedAgain != loaded {
		return NativeInvocationProof{}, errNativeInvocation
	}
	last, err := o.inspect(ctx, InspectRequest{Name: reader.LoadedName, CiphertextDirectory: o.root, ExpectedUID: o.ownerUID})
	if err != nil || last != before || ctx.Err() != nil {
		return NativeInvocationProof{}, errNativeInvocation
	}
	return NativeInvocationProof{BootID: after.BootID, InvocationID: after.InvocationID, MainPID: after.MainPID, ProcessStartTicks: process.StartTicks,
		NamespaceDevice: process.NamespaceDevice, NamespaceInode: process.NamespaceInode,
		CredentialDevice: loaded.Device, CredentialInode: loaded.Inode, CredentialUID: loaded.OwnerUID, CredentialGID: loaded.OwnerGID, CredentialMode: loaded.Mode,
		SourceDevice: before.Device, SourceInode: before.Inode, SourceFingerprint: before.Fingerprint}, nil
}

func sameInvocation(a, b AppliedUnitSnapshot) bool {
	return a.UnitName == b.UnitName && a.MachineID == b.MachineID && a.BootID == b.BootID && a.InvocationID == b.InvocationID &&
		a.MainPID == b.MainPID && a.ExecMainStartMonotonicUSec == b.ExecMainStartMonotonicUSec && a.User == b.User && a.Group == b.Group &&
		a.ActiveState == "active" && b.ActiveState == "active" && !a.NeedDaemonReload && !b.NeedDaemonReload
}

func unitIdentityMatches(snapshot AppliedUnitSnapshot, reader credentialref.NativeConsumerBinding) bool {
	if snapshot.User == "" || snapshot.Group == "" {
		return false
	}
	uid, err := osUserID(snapshot.User)
	if err != nil || uid != reader.ServiceUID {
		return false
	}
	gid, err := osGroupID(snapshot.Group)
	return err == nil && gid == reader.ServiceGID
}

func osUserID(name string) (uint32, error) {
	if number, err := strconv.ParseUint(name, 10, 32); err == nil {
		return uint32(number), nil
	}
	account, err := user.Lookup(name)
	if err != nil {
		return 0, err
	}
	number, err := strconv.ParseUint(account.Uid, 10, 32)
	return uint32(number), err
}

func osGroupID(name string) (uint32, error) {
	if number, err := strconv.ParseUint(name, 10, 32); err == nil {
		return uint32(number), nil
	}
	group, err := user.LookupGroup(name)
	if err != nil {
		return 0, err
	}
	number, err := strconv.ParseUint(group.Gid, 10, 32)
	return uint32(number), err
}

func observeProcessIdentity(ctx context.Context, snapshot AppliedUnitSnapshot, reader credentialref.NativeConsumerBinding) (ProcessIdentity, error) {
	if ctx == nil || ctx.Err() != nil || snapshot.MainPID <= 1 || snapshot.MainPID > 0x7fffffff || !unitIdentityMatches(snapshot, reader) {
		return ProcessIdentity{}, errNativeInvocation
	}
	path := fmt.Sprintf("/proc/%d", snapshot.MainPID)
	stat, err := os.ReadFile(path + "/stat")
	if err != nil {
		return ProcessIdentity{}, errNativeInvocation
	}
	end := bytes.LastIndexByte(stat, ')')
	if end < 0 || end+2 >= len(stat) {
		return ProcessIdentity{}, errNativeInvocation
	}
	fields := strings.Fields(string(stat[end+2:]))
	if len(fields) <= 19 {
		return ProcessIdentity{}, errNativeInvocation
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || start == 0 {
		return ProcessIdentity{}, errNativeInvocation
	}
	status, err := os.ReadFile(path + "/status")
	if err != nil || !procStatusIdentityMatches(string(status), reader.ServiceUID, reader.ServiceGID) {
		return ProcessIdentity{}, errNativeInvocation
	}
	namespace, err := os.Stat(path + "/ns/mnt")
	if err != nil {
		return ProcessIdentity{}, errNativeInvocation
	}
	sys, ok := namespace.Sys().(*unix.Stat_t)
	if !ok || sys.Ino == 0 {
		return ProcessIdentity{}, errNativeInvocation
	}
	request := AccessProbeRequest{UID: reader.ServiceUID, GID: reader.ServiceGID, UnitName: reader.UnitName, CredentialName: reader.LoadedName,
		MainPID: int(snapshot.MainPID), ProcessStartTicks: start, BootID: snapshot.BootID}
	if verifyTargetProcess(request) != nil || ctx.Err() != nil {
		return ProcessIdentity{}, errNativeInvocation
	}
	return ProcessIdentity{MainPID: snapshot.MainPID, StartTicks: start, UID: reader.ServiceUID, GID: reader.ServiceGID,
		NamespaceDevice: uint64(sys.Dev), NamespaceInode: sys.Ino}, nil
}

func procStatusIdentityMatches(status string, uid, gid uint32) bool {
	seenUID, seenGID := false, false
	for _, line := range strings.Split(status, "\n") {
		if !strings.HasPrefix(line, "Uid:") && !strings.HasPrefix(line, "Gid:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 5 {
			return false
		}
		expected := uid
		if fields[0] == "Gid:" {
			expected = gid
			seenGID = true
		} else {
			seenUID = true
		}
		for _, field := range fields[1:] {
			value, err := strconv.ParseUint(field, 10, 32)
			if err != nil || uint32(value) != expected {
				return false
			}
		}
	}
	return seenUID && seenGID
}
