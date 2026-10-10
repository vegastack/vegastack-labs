//go:build linux

package qualification

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

func ownedFile(path string, uid uint32, limit int64) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uid || st.Nlink != 1 || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > limit {
		return nil, ErrUnavailable
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if int64(len(raw)) > limit {
		return nil, ErrUnavailable
	}
	return raw, err
}
func ownedDirectory(path string, uid uint32) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return ErrUnavailable
	}
	// Root and system ancestors may be root-owned; the fixture root itself must
	// belong to the explicit invoking nonroot operator with no shared access.
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return ErrUnavailable
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return ErrUnavailable
		}
		if current == path {
			if st.Uid != uid || info.Mode().Perm() != 0700 {
				return ErrUnavailable
			}
		} else if st.Uid != 0 && st.Uid != uid || info.Mode().Perm()&0022 != 0 {
			return ErrUnavailable
		}
		if current == "/" {
			break
		}
	}
	return nil
}
func processStart(pid int) (uint64, error) {
	raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0, err
	}
	if len(raw) > 8192 {
		return 0, ErrUnavailable
	}
	end := strings.LastIndexByte(string(raw), ')')
	if end < 0 {
		return 0, ErrUnavailable
	}
	fields := strings.Fields(string(raw[end+1:]))
	if len(fields) < 20 {
		return 0, ErrUnavailable
	}
	ticks, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || ticks == 0 {
		return 0, ErrUnavailable
	}
	return ticks, nil
}
func fileDigest(path string, limit int64) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return "", ErrUnavailable
	}
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(f, limit+1))
	if err != nil || n > limit {
		return "", ErrUnavailable
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}
func fileOwner(info os.FileInfo) (uint32, bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Uid, true
}
