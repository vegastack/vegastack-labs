//go:build linux

package qualification

import (
	"golang.org/x/sys/unix"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

func validateOuterConfinement(s validatedNativeScope) error {
	if os.Geteuid() == 0 {
		return ErrUnavailable
	}
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) != 1 || interfaces[0].Name != "lo" || interfaces[0].Flags&net.FlagLoopback == 0 {
		return ErrUnavailable
	}
	var rootFS unix.Statfs_t
	if unix.Statfs("/", &rootFS) != nil || rootFS.Flags&unix.ST_RDONLY == 0 {
		return ErrUnavailable
	}
	status, err := os.ReadFile("/proc/self/status")
	if err != nil || len(status) > 32768 {
		return ErrUnavailable
	}
	caps := false
	for _, line := range strings.Split(string(status), "\n") {
		if strings.HasPrefix(line, "CapEff:") {
			fields := strings.Fields(line)
			if len(fields) != 2 || fields[1] != "0000000000000000" {
				return ErrUnavailable
			}
			caps = true
		}
	}
	if !caps {
		return ErrUnavailable
	}
	read := func(path string) (string, error) {
		raw, e := os.ReadFile(path)
		if e != nil || len(raw) > 128 {
			return "", ErrUnavailable
		}
		return strings.TrimSpace(string(raw)), nil
	}
	memory, e := read("/sys/fs/cgroup/memory.max")
	if e != nil {
		return e
	}
	max, e := strconv.ParseInt(memory, 10, 64)
	if e != nil || max != s.value.Resources.MemoryBytes || max < GiB {
		return ErrUnavailable
	}
	current, e := read("/sys/fs/cgroup/memory.current")
	if e != nil {
		return e
	}
	used, e := strconv.ParseInt(current, 10, 64)
	if e != nil || used < 0 || used > max {
		return ErrUnavailable
	}
	cpu, e := read("/sys/fs/cgroup/cpu.max")
	if e != nil {
		return e
	}
	parts := strings.Fields(cpu)
	if len(parts) != 2 {
		return ErrUnavailable
	}
	quota, e := strconv.ParseInt(parts[0], 10, 64)
	if e != nil {
		return ErrUnavailable
	}
	period, e := strconv.ParseInt(parts[1], 10, 64)
	if e != nil || period <= 0 || quota <= 0 || quota > 6*period || quota < s.value.Resources.CPUs*period {
		return ErrUnavailable
	}
	var storage unix.Statfs_t
	if unix.Statfs(s.value.OutputRoot, &storage) != nil || storage.Bsize <= 0 {
		return ErrUnavailable
	}
	entries, err := os.ReadDir(s.value.OutputRoot)
	if err != nil || len(entries) > 512 {
		return ErrUnavailable
	}
	var allocated uint64
	for _, entry := range entries {
		info, e := os.Lstat(filepath.Join(s.value.OutputRoot, entry.Name()))
		if e != nil {
			return ErrUnavailable
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return ErrUnavailable
		}
		if !info.Mode().IsRegular() {
			continue
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Blocks < 0 {
			return ErrUnavailable
		}
		allocated += uint64(st.Blocks) * 512
		if allocated > uint64(s.value.Resources.StorageBytes) {
			return ErrUnavailable
		}
	}
	available := uint64(storage.Bavail) * uint64(storage.Bsize)
	if available < uint64(s.value.Resources.StorageBytes)-allocated {
		return ErrUnavailable
	}
	return nil
}
