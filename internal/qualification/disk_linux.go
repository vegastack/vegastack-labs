//go:build linux

package qualification

import (
	"context"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

// checkOwnedDisk confines all disk access to prepared one-layer images. A
// prepared reset image is independently digest pinned; writable guest bytes
// are never confused with their initial content digest.
func (d *ownedGuestLifecycle) checkOwnedDisk(ctx context.Context, id string) error {
	var baseFS unix.Statfs_t
	if unix.Statfs("/inputs", &baseFS) != nil || baseFS.Flags&unix.ST_RDONLY == 0 {
		return ErrUnavailable
	}
	baseInfo, baseErr := os.Lstat("/inputs/base.qcow2")
	if baseErr != nil || !baseInfo.Mode().IsRegular() || baseInfo.Mode().Perm()&0022 != 0 {
		return ErrUnavailable
	}
	baseDigest, baseErr := fileDigest("/inputs/base.qcow2", 36*GiB)
	if baseErr != nil || baseDigest != d.scope.value.ImageDigest {
		return ErrUnavailable
	}
	guest, ok := d.scope.guests[id]
	if !ok {
		return ErrUnavailable
	}
	for _, suffix := range []string{".qcow2", ".prepared.qcow2", ".vars.fd", ".prepared.vars.fd"} {
		path := filepath.Join(d.scope.value.OutputRoot, id+suffix)
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			return ErrUnavailable
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != uint32(os.Geteuid()) || st.Nlink != 1 {
			return ErrUnavailable
		}
	}
	liveInfo, e := os.Lstat(filepath.Join(d.scope.value.OutputRoot, id+".qcow2"))
	if e != nil {
		return ErrUnavailable
	}
	if previous := d.diskInfo[id]; previous != nil && !os.SameFile(previous, liveInfo) {
		return ErrUnavailable
	}
	d.diskInfo[id] = liveInfo
	variableInfo, e := os.Lstat(filepath.Join(d.scope.value.OutputRoot, id+".vars.fd"))
	if e != nil {
		return e
	}
	if previous := d.variablesInfo[id]; previous != nil && !os.SameFile(previous, variableInfo) {
		return ErrUnavailable
	}
	d.variablesInfo[id] = variableInfo
	code, e := fileDigest("/usr/share/edk2/ovmf/OVMF_CODE.fd", 16*1024*1024)
	if e != nil {
		return e
	}
	variables, e := fileDigest(filepath.Join(d.scope.value.OutputRoot, id+".prepared.vars.fd"), 16*1024*1024)
	if e != nil {
		return e
	}
	firmware := struct {
		CodeDigest      string `json:"codeDigest"`
		VariablesDigest string `json:"variablesDigest"`
	}{code, variables}
	if hostaction.Digest(firmware) != guest.FirmwareDigest {
		return ErrUnavailable
	}
	digest, err := fileDigest(filepath.Join(d.scope.value.OutputRoot, id+".prepared.qcow2"), guest.DiskBytes+GiB)
	if err != nil || digest != guest.DiskDigest {
		return ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	for _, path := range []string{"/inputs/base.qcow2", filepath.Join(d.scope.value.OutputRoot, id+".qcow2"), filepath.Join(d.scope.value.OutputRoot, id+".prepared.qcow2")} {
		command := exec.CommandContext(ctx, "/usr/bin/qemu-img", "info", "--force-share", "--output=json", path)
		pipe, err := command.StdoutPipe()
		if err != nil {
			return err
		}
		command.Stderr = io.Discard
		if command.Start() != nil {
			return ErrUnavailable
		}
		raw, readErr := io.ReadAll(io.LimitReader(pipe, 16385))
		if len(raw) > 16384 {
			_ = command.Process.Kill()
		}
		waitErr := command.Wait()
		if readErr != nil || waitErr != nil || len(raw) > 16384 || validateQEMUImageInfo(raw, path == "/inputs/base.qcow2", guest.DiskBytes) != nil {
			return ErrUnavailable
		}
	}
	return nil
}

// validateQEMUImageInfo rejects hidden ancestors behind the immutable base.
func validateQEMUImageInfo(raw []byte, base bool, size int64) error {
	var info struct {
		Format        string `json:"format"`
		VirtualSize   int64  `json:"virtual-size"`
		Backing       string `json:"backing-filename"`
		FullBacking   string `json:"full-backing-filename"`
		BackingFormat string `json:"backing-filename-format"`
	}
	if json.Unmarshal(raw, &info) != nil || info.Format != "qcow2" || info.VirtualSize <= 0 {
		return ErrUnavailable
	}
	if base {
		if info.VirtualSize > 36*GiB || info.Backing != "" || info.FullBacking != "" || info.BackingFormat != "" {
			return ErrUnavailable
		}
	} else if info.VirtualSize != size || info.Backing != "/inputs/base.qcow2" || info.FullBacking != "/inputs/base.qcow2" || info.BackingFormat != "qcow2" {
		return ErrUnavailable
	}
	return nil
}

// ResetStoppedOwnedDisk restores only the exact prepared fixture copy. This
// never opens a control database and is not product recovery or data restore.
func (d *ownedGuestLifecycle) ResetStoppedOwnedDisk(ctx context.Context, id string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	launch, ok := d.launches[id]
	if !ok {
		return ErrUnavailable
	}
	if _, err := os.Stat("/proc/" + strconv.FormatInt(launch.QEMUPID, 10)); !os.IsNotExist(err) {
		return ErrUnavailable
	}
	if err := d.checkOwnedDisk(ctx, id); err != nil {
		return err
	}
	pending := filepath.Join(d.scope.value.OutputRoot, id+".reset-pending.json")
	journalFD, err := unix.Open(pending, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	journal := os.NewFile(uintptr(journalFD), pending)
	raw, _ := json.Marshal(struct{ Scope, Guest, Disk, Firmware string }{d.scope.digest, id, d.scope.guests[id].DiskDigest, d.scope.guests[id].FirmwareDigest})
	_, err = journal.Write(raw)
	syncErr := journal.Sync()
	closeErr := journal.Close()
	if err != nil || syncErr != nil || closeErr != nil {
		return ErrUnavailable
	}
	parent, err := os.Open(d.scope.value.OutputRoot)
	if err != nil {
		return err
	}
	syncErr = parent.Sync()
	closeErr = parent.Close()
	if syncErr != nil || closeErr != nil {
		return ErrUnavailable
	}
	source := filepath.Join(d.scope.value.OutputRoot, id+".prepared.qcow2")
	fd, err := unix.Open(source, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	input := os.NewFile(uintptr(fd), source)
	defer input.Close()
	temporary := filepath.Join(d.scope.value.OutputRoot, id+".reset-pending.qcow2")
	fd, err = unix.Open(temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	output := os.NewFile(uintptr(fd), temporary)
	complete := false
	defer func() {
		output.Close()
		if !complete {
			os.Remove(temporary)
		}
	}()
	limit := d.scope.guests[id].DiskBytes + GiB
	n, err := io.Copy(output, io.LimitReader(input, limit+1))
	if err != nil || n > limit || ctx.Err() != nil {
		return ErrUnavailable
	}
	if output.Sync() != nil || output.Close() != nil {
		return ErrUnavailable
	}
	digest, err := fileDigest(temporary, limit)
	if err != nil || digest != d.scope.guests[id].DiskDigest {
		return ErrUnavailable
	}
	if err = os.Rename(temporary, filepath.Join(d.scope.value.OutputRoot, id+".qcow2")); err != nil {
		return err
	}
	complete = true
	d.diskInfo[id], err = os.Lstat(filepath.Join(d.scope.value.OutputRoot, id+".qcow2"))
	if err != nil {
		return err
	}
	if err = d.resetVariables(ctx, id); err != nil {
		return err
	}
	d.variablesInfo[id], err = os.Lstat(filepath.Join(d.scope.value.OutputRoot, id+".vars.fd"))
	if err != nil {
		return err
	}
	delete(d.bootIDs, id)
	delete(d.bootAt, id)
	directory, err := os.Open(d.scope.value.OutputRoot)
	if err != nil {
		return err
	}
	defer directory.Close()
	if err = directory.Sync(); err != nil {
		return err
	}
	if err = os.Remove(pending); err != nil {
		return err
	}
	return directory.Sync()
}

func (d *ownedGuestLifecycle) resetVariables(ctx context.Context, id string) error {
	source := filepath.Join(d.scope.value.OutputRoot, id+".prepared.vars.fd")
	raw, err := ownedFile(source, uint32(os.Geteuid()), 16*1024*1024)
	if err != nil || ctx.Err() != nil {
		return ErrUnavailable
	}
	target := filepath.Join(d.scope.value.OutputRoot, id+".reset-pending.vars.fd")
	fd, err := unix.Open(target, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), target)
	_, err = f.Write(raw)
	syncErr := f.Sync()
	closeErr := f.Close()
	if err != nil || syncErr != nil || closeErr != nil {
		return ErrUnavailable
	}
	return os.Rename(target, filepath.Join(d.scope.value.OutputRoot, id+".vars.fd"))
}
