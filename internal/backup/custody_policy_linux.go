//go:build linux

package backup

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// CustodyPolicy is a host-administrator-owned Linux profile, never a plan or
// declaration field. It fixes every filesystem and OS identity before a lease
// can name one of the two registered repositories.
type CustodyPolicy struct {
	SchemaVersion      string        `json:"schemaVersion"`
	StandardRoot       string        `json:"standardRoot"`
	CriticalRoot       string        `json:"criticalRoot"`
	StandardQuarantine string        `json:"standardQuarantine"`
	CriticalQuarantine string        `json:"criticalQuarantine"`
	OwnerUID           uint32        `json:"ownerUid"`
	OwnerGID           uint32        `json:"ownerGid"`
	ControllerUID      uint32        `json:"controllerUid"`
	ResticUID          uint32        `json:"resticUid"`
	RequestRoot        string        `json:"requestRoot"`
	ExchangeRoot       string        `json:"exchangeRoot"`
	UnitTemplate       string        `json:"unitTemplate"`
	ExecutablePath     string        `json:"executablePath"`
	ResticBinaryPath   string        `json:"resticBinaryPath"`
	ExecutableDigest   string        `json:"executableDigest"`
	MaximumLifetime    time.Duration `json:"maximumLifetime"`
}

const maxCustodyPolicyBytes = 16 << 10

// LoadCustodyPolicy reads an exact root-owned policy through a no-symlink FD.
// Every ancestor is root-owned and non-writable by untrusted identities.
func LoadCustodyPolicy(path string) (CustodyPolicy, error) {
	if !cleanCustodyPath(path) {
		return CustodyPolicy{}, unix.EINVAL
	}
	fd, err := openCustodyPath(path, false, 0)
	if err != nil {
		return CustodyPolicy{}, err
	}
	file := os.NewFile(uintptr(fd), "custody-policy")
	if file == nil {
		_ = unix.Close(fd)
		return CustodyPolicy{}, unix.EBADF
	}
	defer file.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Uid != 0 || stat.Mode&0o022 != 0 || stat.Mode&0o004 == 0 || hasCustodyACL(fd, false) {
		return CustodyPolicy{}, unix.EPERM
	}
	data, err := io.ReadAll(io.LimitReader(file, maxCustodyPolicyBytes+1))
	if err != nil || len(data) == 0 || len(data) > maxCustodyPolicyBytes {
		return CustodyPolicy{}, unix.EINVAL
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	var policy CustodyPolicy
	if err := decoder.Decode(&policy); err != nil {
		return CustodyPolicy{}, unix.EINVAL
	}
	var extra any
	if !errors.Is(decoder.Decode(&extra), io.EOF) || !validCustodyPolicy(policy) {
		return CustodyPolicy{}, unix.EINVAL
	}
	if err := verifyCustodyExecutable(policy.ExecutableDigest); err != nil {
		return CustodyPolicy{}, err
	}
	configured, err := openCustodyPath(policy.ExecutablePath, false, 0)
	if err != nil {
		return CustodyPolicy{}, err
	}
	defer unix.Close(configured)
	running, err := unix.Open("/proc/self/exe", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return CustodyPolicy{}, err
	}
	defer unix.Close(running)
	var configuredStat, runningStat unix.Stat_t
	if unix.Fstat(configured, &configuredStat) != nil || unix.Fstat(running, &runningStat) != nil ||
		configuredStat.Dev != runningStat.Dev || configuredStat.Ino != runningStat.Ino {
		return CustodyPolicy{}, unix.EPERM
	}
	return policy, nil
}

// VerifyCustodyPaths checks the four predeclared local directories. Mode 0700
// and no ACL, combined with disjoint UIDs and root-owned ancestors, deny the
// controller and restic direct traversal, including rename and chmod by path.
func VerifyCustodyPaths(policy CustodyPolicy, role string) error {
	if err := verifyRepositoryCustodyPaths(policy, role); err != nil {
		return err
	}
	for index, path := range []string{policy.RequestRoot, policy.ExchangeRoot} {
		fd, err := openCustodyPath(path, true, policy.ControllerUID)
		if err != nil {
			return err
		}
		var stat unix.Stat_t
		statErr := unix.Fstat(fd, &stat)
		acl := hasCustodyACL(fd, true)
		local := isLocalDescriptor(fd)
		_ = unix.Close(fd)
		expectedMode := uint32(0o700)
		if index == 1 {
			// The restic child must traverse the exchange root to one fresh,
			// random owner-only directory; 0711 permits traversal without
			// listing or creating siblings.
			expectedMode = 0o711
		}
		if statErr != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Gid != policy.ControllerUID || stat.Mode&0o7777 != expectedMode || acl || !local {
			return unix.EPERM
		}
	}
	return nil
}

func verifyRepositoryCustodyPaths(policy CustodyPolicy, role string) error {
	if !validCustodyPolicy(policy) || (role != "writer" && role != "verifier" && role != "retention" && role != "offsite-writer" && role != "offsite-verifier") {
		return unix.EINVAL
	}
	var devices [4]uint64
	for index, path := range []string{policy.StandardRoot, policy.CriticalRoot, policy.StandardQuarantine, policy.CriticalQuarantine} {
		fd, err := openCustodyPath(path, true, policy.OwnerUID)
		if err != nil {
			return err
		}
		var stat unix.Stat_t
		statErr := unix.Fstat(fd, &stat)
		acl := hasCustodyACL(fd, true)
		local := isLocalDescriptor(fd)
		_ = unix.Close(fd)
		if statErr != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != policy.OwnerUID || stat.Gid != policy.OwnerGID || stat.Mode&0o7777 != 0o700 || acl || !local {
			return unix.EPERM
		}
		devices[index] = uint64(stat.Dev)
	}
	if devices[0] != devices[2] || devices[1] != devices[3] {
		return unix.EXDEV
	}
	return nil
}

func validCustodyPolicy(policy CustodyPolicy) bool {
	if policy.SchemaVersion != "1.0.0" || policy.OwnerUID == 0 || policy.OwnerGID == 0 ||
		policy.ControllerUID == 0 || policy.ResticUID == 0 ||
		policy.OwnerUID == policy.ControllerUID || policy.OwnerUID == policy.ResticUID || policy.ControllerUID == policy.ResticUID ||
		policy.MaximumLifetime < time.Second || policy.MaximumLifetime > 30*time.Minute ||
		policy.UnitTemplate != "vsk-labs-backup-custody@.service" || !cleanCustodyPath(policy.ExecutablePath) || !cleanCustodyPath(policy.ResticBinaryPath) ||
		len(policy.ExecutableDigest) != len("sha256:")+64 || !strings.HasPrefix(policy.ExecutableDigest, "sha256:") {
		return false
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(policy.ExecutableDigest, "sha256:")); err != nil {
		return false
	}
	seen := map[string]bool{}
	for _, path := range []string{policy.StandardRoot, policy.CriticalRoot, policy.StandardQuarantine, policy.CriticalQuarantine, policy.RequestRoot, policy.ExchangeRoot, policy.ExecutablePath, policy.ResticBinaryPath} {
		if !cleanCustodyPath(path) || seen[path] {
			return false
		}
		seen[path] = true
	}
	return true
}

func cleanCustodyPath(path string) bool {
	return len(path) >= 2 && len(path) <= 4096 && filepath.IsAbs(path) && filepath.Clean(path) == path && path != "/" && !strings.ContainsRune(path, 0)
}

// openCustodyPath descends from / by descriptor so no component can be a
// symlink; each parent must be a root-owned, ACL-free, non-writable directory.
func openCustodyPath(path string, directory bool, finalUID uint32) (int, error) {
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for index, part := range parts {
		var stat unix.Stat_t
		if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != 0 || stat.Mode&0o022 != 0 || hasCustodyACL(fd, true) {
			_ = unix.Close(fd)
			return -1, unix.EPERM
		}
		flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW
		if index < len(parts)-1 || directory {
			flags |= unix.O_DIRECTORY
		}
		next, err := unix.Openat(fd, part, flags, 0)
		_ = unix.Close(fd)
		if err != nil {
			return -1, err
		}
		fd = next
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Uid != finalUID {
		_ = unix.Close(fd)
		return -1, unix.EPERM
	}
	return fd, nil
}

func hasCustodyACL(fd int, directory bool) bool {
	for _, name := range []string{"system.posix_acl_access", "system.posix_acl_default"} {
		if name == "system.posix_acl_default" && !directory {
			continue
		}
		if _, err := unix.Fgetxattr(fd, name, nil); err == nil || !errors.Is(err, unix.ENODATA) {
			return true
		}
	}
	return false
}

func verifyCustodyExecutable(expected string) error {
	// /proc/self/exe names the inode actually executing; reopening a pathname
	// returned by os.Executable could hash a different inode after replacement.
	file, err := os.Open("/proc/self/exe")
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 256<<20 ||
		stat.Uid != 0 || stat.Nlink != 1 || info.Mode().Perm()&0o022 != 0 {
		return unix.EPERM
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, io.LimitReader(file, 256<<20)); err != nil {
		return err
	}
	if "sha256:"+hex.EncodeToString(hash.Sum(nil)) != expected {
		return unix.EPERM
	}
	return nil
}
