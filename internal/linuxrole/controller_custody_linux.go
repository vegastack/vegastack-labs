//go:build linux

package linuxrole

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"slices"
	"sort"

	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"golang.org/x/sys/unix"
)

type controllerMetadata struct {
	Device uint64
	Inode  uint64
	UID    uint32
	GID    uint32
	Mode   uint32
	Links  uint64
}

func metadataOf(s unix.Stat_t) controllerMetadata {
	return controllerMetadata{uint64(s.Dev), s.Ino, s.Uid, s.Gid, s.Mode, s.Nlink}
}
func controllerCredentialPaths(in ControllerInstallInput) []string {
	paths := []string{"/etc/vsk-labs/control", "/etc/vsk-labs/control/credentials"}
	for _, name := range in.SlackCredentialNames {
		paths = append(paths, "/etc/vsk-labs/control/credentials/"+name)
	}
	return paths
}

// ObserveControllerCredentialCustody returns only fixed artifact metadata. It
// never reads credential bytes or computes a digest of secret material.
func ObserveControllerCredentialCustody(in ControllerInstallInput) (string, error) {
	if ValidateControllerInstallInput(in) != nil {
		return "", errInput
	}
	facts, e := controllerCredentialMetadata(in)
	if e != nil {
		return "", e
	}
	return hostaction.Digest(facts), nil
}
func controllerCredentialMetadata(in ControllerInstallInput) ([]controllerMetadata, error) {
	if ownedAncestors("/etc/vsk-labs/control", in.AdministratorUID) != nil {
		return nil, errNative
	}
	facts := []controllerMetadata{}
	for i, p := range controllerCredentialPaths(in) {
		var s unix.Stat_t
		if unix.Lstat(p, &s) != nil || s.Uid != 0 && s.Uid != uint32(in.AdministratorUID) {
			return nil, errNative
		}
		if i < 2 {
			if s.Mode&unix.S_IFMT != unix.S_IFDIR || s.Mode&0777 != 0700 && !(i == 0 && s.Mode&0777 == 0750) {
				return nil, errNative
			}
		} else if s.Mode&unix.S_IFMT != unix.S_IFREG || s.Mode&0777 != 0600 || s.Nlink != 1 {
			return nil, errNative
		}
		facts = append(facts, metadataOf(s))
	}
	entries, e := os.ReadDir("/etc/vsk-labs/control/credentials")
	if e != nil {
		return nil, e
	}
	names := []string{}
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	if !slices.Equal(names, in.SlackCredentialNames) {
		return nil, errNative
	}
	return facts, nil
}
func moveControllerCredentialCustody(ctx context.Context, in ControllerInstallInput) (bool, error) {
	facts, e := controllerCredentialMetadata(in)
	if e != nil || hostaction.Digest(facts) != in.CredentialCustodyDigest {
		return false, errNative
	}
	fds := []int{}
	defer func() {
		for _, fd := range fds {
			unix.Close(fd)
		}
	}()
	for i, p := range controllerCredentialPaths(in) {
		fd, e := unix.Openat2(unix.AT_FDCWD, p, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW, Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
		if e != nil {
			return false, errNative
		}
		fds = append(fds, fd)
		var s unix.Stat_t
		if unix.Fstat(fd, &s) != nil || metadataOf(s) != facts[i] {
			return false, errNative
		}
	}
	// Preserve the exact finite metadata before changing custody. This record
	// contains no plaintext, secret digest or authorization substitute.
	record, _ := json.Marshal(struct {
		InputDigest string
		Paths       []string
		Before      []controllerMetadata
	}{hostaction.Digest(in), controllerCredentialPaths(in), facts})
	recordPath := "var/lib/vsk-labs/access-rollback/controller-pilot-credentials.before.json"
	prior, re := readProtected("/", recordPath, 65536)
	if re == nil && !bytes.Equal(prior, record) || re != nil && !os.IsNotExist(re) {
		return false, errNative
	}
	changed := false
	if os.IsNotExist(re) {
		if e = writeControllerArtifact(ctx, "/", recordPath, record, 0600, 0, false); e != nil {
			return false, e
		}
		changed = true
	}
	for i, fd := range fds {
		gid, mode := 0, uint32(0600)
		if i == 0 {
			gid, mode = int(in.AdministratorGID), 0750
		}
		if i == 1 {
			mode = 0700
		}
		if facts[i].UID != 0 || facts[i].GID != uint32(gid) || facts[i].Mode&0777 != mode {
			changed = true
			if unix.Fchown(fd, 0, gid) != nil || unix.Fchmod(fd, mode) != nil || unix.Fsync(fd) != nil {
				return changed, errNative
			}
		}
	}
	return changed, nil
}
