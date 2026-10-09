//go:build linux

package qualification

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"golang.org/x/sys/unix"
)

type ownedGuestLifecycle struct {
	activeController    string
	recoveredController *generated.NativeControllerIdentity
	recoveredBinding    *generated.RestoreBinding
	replacement         *nativeReplacementMemory
	scope               validatedNativeScope
	mu                  sync.Mutex
	launches            map[string]generated.NativeGuestLaunch
	bootIDs             map[string]string
	bootAt              map[string]time.Time
	diskInfo            map[string]os.FileInfo
	variablesInfo       map[string]os.FileInfo
	witnesses           map[string]*nativeWitnessMemory
}

// QEMUArguments is the finite launch template shared with the private
// coordinator. There is no caller-supplied argv, NIC backend or executable.
func QEMUArguments(scope generated.QualificationScope, id string) ([]string, error) {
	s, err := validateScope(scope)
	if err != nil {
		return nil, err
	}
	g, ok := s.guests[id]
	if !ok {
		return nil, ErrUnavailable
	}
	root := s.value.OutputRoot
	args := []string{"-name", "vsk228-" + id, "-smbios", "type=1,serial=" + g.InstanceID, "-nodefaults", "-machine", "q35", "-accel", "kvm", "-cpu", "host", "-no-reboot", "-smp", strconv.FormatInt(g.CPUs, 10), "-m", strconv.FormatInt(g.MemoryBytes/(1024*1024), 10), "-display", "none", "-monitor", "none", "-no-user-config", "-sandbox", "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny", "-drive", "if=pflash,format=raw,readonly=on,file=/usr/share/edk2/ovmf/OVMF_CODE.fd", "-drive", "if=pflash,format=raw,file=" + filepath.Join(root, id+".vars.fd"), "-drive", "file=" + filepath.Join(root, id+".qcow2") + ",format=qcow2,if=virtio", "-qmp", "unix:" + filepath.Join(root, id+".qmp") + ",server=on,wait=off", "-chardev", "socket,id=console,path=" + filepath.Join(root, id+".serial") + ",server=on,wait=off", "-serial", "chardev:console", "-device", "virtio-serial-pci", "-chardev", "socket,id=observer,path=" + filepath.Join(root, id+".observer") + ",server=on,wait=off", "-device", "virtserialport,chardev=observer,name=vsk.native.observer"}
	// Only loopback point-to-point guest links inside network-none confinement.
	ports := map[string]int{"subject": 19281, "custodian": 19283, "replacement": 19284}
	for _, role := range []string{"subject", "custodian", "replacement"} {
		present := false
		for _, other := range s.guests {
			if other.Role == role {
				present = true
			}
		}
		if !present {
			continue
		}
		localPort, peerPort := ports[role]+100, ports[role]
		if g.Role == "controller" {
			localPort, peerPort = peerPort, localPort
		} else if g.Role != role {
			continue
		}
		macRole := ports[role] - 19280
		last := "02"
		if g.Role == "controller" {
			last = "01"
		}
		args = append(args, "-netdev", "socket,id="+role+",udp=127.0.0.1:"+strconv.Itoa(peerPort)+",localaddr=127.0.0.1:"+strconv.Itoa(localPort), "-device", "virtio-net-pci,netdev="+role+",mac=52:54:00:28:0"+strconv.Itoa(macRole)+":"+last)
	}
	if g.Role == "controller" || g.Role == "subject" {
		localPort, peerPort, last := 19382, 19282, "02"
		if g.Role == "controller" {
			localPort, peerPort, last = peerPort, localPort, "01"
		}
		args = append(args, "-netdev", "socket,id=denied,udp=127.0.0.1:"+strconv.Itoa(peerPort)+",localaddr=127.0.0.1:"+strconv.Itoa(localPort), "-device", "virtio-net-pci,netdev=denied,mac=52:54:00:28:02:"+last)
	}
	// The recovered controller must reach the subject and custodian directly
	// while the former controller is fenced. These are still finite UDP peers
	// on container loopback, with no bridge, router or external network backend.
	for _, pair := range []struct {
		role, id, mac string
		port          int
	}{
		{"subject", "recovery-subject", "05", 19285},
		{"custodian", "recovery-custodian", "06", 19286},
	} {
		replacementPresent, peerPresent := false, false
		for _, guest := range s.guests {
			replacementPresent = replacementPresent || guest.Role == "replacement"
			peerPresent = peerPresent || guest.Role == pair.role
		}
		if !replacementPresent || !peerPresent || (g.Role != "replacement" && g.Role != pair.role) {
			continue
		}
		local, remote, last := pair.port, pair.port+100, "01"
		if g.Role == pair.role {
			local, remote, last = remote, local, "02"
		}
		args = append(args, "-netdev", "socket,id="+pair.id+",udp=127.0.0.1:"+strconv.Itoa(remote)+",localaddr=127.0.0.1:"+strconv.Itoa(local), "-device", "virtio-net-pci,netdev="+pair.id+",mac=52:54:00:28:"+pair.mac+":"+last)
	}
	return args, nil
}
func newOwnedGuestLifecycle(ctx context.Context, scope validatedNativeScope) (*ownedGuestLifecycle, error) {
	if os.Geteuid() == 0 || ownedDirectory(scope.value.OutputRoot, uint32(os.Geteuid())) != nil {
		return nil, ErrUnavailable
	}
	d := &ownedGuestLifecycle{scope: scope, launches: map[string]generated.NativeGuestLaunch{}, bootIDs: map[string]string{}, bootAt: map[string]time.Time{}, diskInfo: map[string]os.FileInfo{}, variablesInfo: map[string]os.FileInfo{}, witnesses: map[string]*nativeWitnessMemory{}}
	for id, g := range scope.guests {
		if g.Role == "controller" {
			d.activeController = id
		}
		if _, e := os.Lstat(filepath.Join(scope.value.OutputRoot, id+".reset-pending.json")); !os.IsNotExist(e) {
			return nil, ErrUnavailable
		}
		raw, err := ownedFile(filepath.Join(scope.value.OutputRoot, id+".launch.json"), uint32(os.Geteuid()), 16384)
		if err != nil {
			return nil, err
		}
		var l generated.NativeGuestLaunch
		if generated.ValidateContractJSON(generated.SchemaIDNativeGuestLaunch, raw, generated.ContractExact) != nil || json.Unmarshal(raw, &l) != nil || l.ScopeDigest != scope.digest || l.GuestID != id || l.DiskDigest != g.DiskDigest || l.FirmwareDigest != g.FirmwareDigest || l.ConsoleReferenceDigest != scope.value.ConsoleReferenceDigest {
			return nil, ErrUnavailable
		}
		d.launches[id] = l
		if err = d.checkOwnedDisk(ctx, id); err != nil {
			return nil, err
		}
		if err = d.checkProcess(id); err != nil {
			return nil, err
		}
	}
	return d, nil
}
func (d *ownedGuestLifecycle) checkProcess(id string) error {
	l, ok := d.launches[id]
	if !ok {
		return ErrUnavailable
	}
	path := filepath.Join(d.scope.value.OutputRoot, id+".qcow2")
	info, e := os.Lstat(path)
	if e != nil || d.diskInfo[id] == nil || !os.SameFile(info, d.diskInfo[id]) {
		return ErrUnavailable
	}
	variables := filepath.Join(d.scope.value.OutputRoot, id+".vars.fd")
	variablesInfo, e := os.Lstat(variables)
	if e != nil || d.variablesInfo[id] == nil || !os.SameFile(variablesInfo, d.variablesInfo[id]) {
		return ErrUnavailable
	}
	ticks, err := processStart(int(l.QEMUPID))
	if err != nil || ticks != uint64(l.QEMUStartTimeTicks) {
		return ErrUnavailable
	}
	proc := "/proc/" + strconv.FormatInt(l.QEMUPID, 10)
	info, err = os.Stat(proc)
	if err != nil {
		return ErrUnavailable
	}
	uid, ok := fileOwner(info)
	if !ok || uid != uint32(os.Geteuid()) {
		return ErrUnavailable
	}
	exe, err := os.Readlink(proc + "/exe")
	if err != nil || exe != "/usr/libexec/qemu-kvm" {
		return ErrUnavailable
	}
	digest, err := fileDigest(proc+"/exe", 256*1024*1024)
	if err != nil || digest != l.QEMUExecutableDigest {
		return ErrUnavailable
	}
	entries, err := os.ReadDir(proc + "/fd")
	if err != nil || len(entries) > 256 {
		return ErrUnavailable
	}
	opened, variablesOpened := false, false
	for _, entry := range entries {
		p := proc + "/fd/" + entry.Name()
		target, e := os.Readlink(p)
		if e != nil {
			continue
		}
		if target == variables {
			fdInfo, e := os.Stat(p)
			if e != nil || !os.SameFile(fdInfo, d.variablesInfo[id]) {
				return ErrUnavailable
			}
			variablesOpened = true
		}
		if target == path {
			fdInfo, e := os.Stat(p)
			if e != nil || !os.SameFile(fdInfo, d.diskInfo[id]) {
				return ErrUnavailable
			}
			opened = true
		}
	}
	if !opened || !variablesOpened {
		return ErrUnavailable
	}
	raw, err := os.ReadFile(proc + "/cmdline")
	if err != nil || len(raw) > 16384 {
		return ErrUnavailable
	}
	got := strings.Split(strings.TrimSuffix(string(raw), "\x00"), "\x00")
	args, err := QEMUArguments(d.scope.value, id)
	if err != nil || len(got) < 1 || got[0] != "/usr/libexec/qemu-kvm" || !reflect.DeepEqual(got[1:], args) {
		return ErrUnavailable
	}
	return nil
}
func (d *ownedGuestLifecycle) RequestPowerdown(ctx context.Context, id string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.checkProcess(id); err != nil {
		return err
	}
	l := d.launches[id]
	_, err := ownedQMP(ctx, filepath.Join(d.scope.value.OutputRoot, id+".qmp"), int(l.QEMUPID), qmpPowerdown)
	return err
}
func (d *ownedGuestLifecycle) StopOwned(ctx context.Context, id string) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if err := d.RequestPowerdown(ctx, id); err != nil {
		return err
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		d.mu.Lock()
		l := d.launches[id]
		d.mu.Unlock()
		ticks, err := processStart(int(l.QEMUPID))
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil || ticks != uint64(l.QEMUStartTimeTicks) {
			return ErrUnavailable
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// RestartOwned only starts the source-defined template after confirmed exit.
// Parent/coordinator remains responsible for recording cleanup on cancellation.
func (d *ownedGuestLifecycle) RestartOwned(ctx context.Context, id string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	l, ok := d.launches[id]
	if !ok {
		return ErrUnavailable
	}
	if _, err := os.Stat("/proc/" + strconv.FormatInt(l.QEMUPID, 10)); !os.IsNotExist(err) {
		return ErrUnavailable
	}
	if _, e := os.Lstat(filepath.Join(d.scope.value.OutputRoot, id+".reset-pending.json")); !os.IsNotExist(e) {
		return ErrUnavailable
	}
	args, err := QEMUArguments(d.scope.value, id)
	if err != nil {
		return err
	}
	for _, suffix := range []string{".qmp", ".serial", ".observer"} {
		p := filepath.Join(d.scope.value.OutputRoot, id+suffix)
		info, e := os.Lstat(p)
		if e == nil {
			uid, ok := fileOwner(info)
			if !ok || uid != uint32(os.Geteuid()) || info.Mode()&os.ModeSocket == 0 {
				return ErrUnavailable
			}
			if e = os.Remove(p); e != nil {
				return e
			}
		} else if !os.IsNotExist(e) {
			return e
		}
	}
	command := exec.Command("/usr/libexec/qemu-kvm", args...)
	command.Dir = d.scope.value.OutputRoot
	if err = command.Start(); err != nil {
		return err
	}
	go func() { _ = command.Wait() }()
	success := false
	defer func() {
		if !success {
			_ = command.Process.Kill()
		}
	}()
	l.QEMUPID = int64(command.Process.Pid)
	ticks, err := processStart(command.Process.Pid)
	if err != nil {
		_ = command.Process.Kill()
		return err
	}
	l.QEMUStartTimeTicks = int64(ticks)
	d.launches[id] = l
	raw, err := json.Marshal(l)
	if err != nil {
		return err
	}
	path := filepath.Join(d.scope.value.OutputRoot, id+".launch.json")
	fd, err := unix.Open(path, unix.O_WRONLY|unix.O_TRUNC|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), path)
	_, err = f.Write(raw)
	syncErr := f.Sync()
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if syncErr != nil {
		return syncErr
	}
	if closeErr != nil {
		return closeErr
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	readyDeadline := time.Now().Add(5 * time.Second)
	for {
		if err := d.checkProcess(id); err == nil {
			break
		}
		if time.Now().After(readyDeadline) {
			return ErrUnavailable
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
	success = true
	return nil
}
