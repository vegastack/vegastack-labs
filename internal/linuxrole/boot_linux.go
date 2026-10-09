//go:build linux

package linuxrole

import (
	"golang.org/x/sys/unix"
	"os"
)

const roleWantsDirectory = "etc/systemd/system/multi-user.target.wants"

func roleSlice(unit string) bool {
	return unit == "vsk-application.slice" || unit == "vsk-ci.slice" || unit == "vsk-standby.slice"
}

// roleBootLink admits only the declared role slice and its exact systemd unit.
// It neither enables a provider unit nor modifies an existing unknown link.
func (n *nativeRuntime) roleBootLink(unit string, create bool) (bool, error) {
	if !roleSlice(unit) {
		return false, errNative
	}
	if _, e := protectedInfo(n.root, "etc/systemd/system"); e != nil {
		return false, e
	}
	fs, e := os.OpenRoot(n.root)
	if e != nil {
		return false, e
	}
	defer fs.Close()
	if _, e = protectedInfo(n.root, roleWantsDirectory); os.IsNotExist(e) && create {
		if e = fs.Mkdir(roleWantsDirectory, 0755); e != nil {
			return false, e
		}
	} else if e != nil {
		return false, e
	}
	p := roleWantsDirectory + "/" + unit
	target := "/etc/systemd/system/" + unit
	st, e := fs.Lstat(p)
	if e == nil {
		if st.Mode()&os.ModeSymlink == 0 {
			return false, errNative
		}
		actual, e := fs.Readlink(p)
		if e != nil || actual != target {
			return false, errNative
		}
		var stat unix.Stat_t
		if unix.Lstat(n.root+"/"+p, &stat) != nil || stat.Uid != uint32(os.Geteuid()) {
			return false, errNative
		}
		return false, nil
	}
	if !os.IsNotExist(e) || !create {
		return false, e
	}
	// Confirm a protected unit exists before creating a boot dependency.
	if _, e = readProtected(n.root, "etc/systemd/system/"+unit, 65536); e != nil {
		return false, e
	}
	if e = fs.Symlink(target, p); e != nil {
		return false, e
	}
	d, e := fs.Open(roleWantsDirectory)
	if e != nil {
		return true, e
	}
	defer d.Close()
	return true, d.Sync()
}
func (n *nativeRuntime) removeRoleBootLink(unit string) error {
	if _, e := n.roleBootLink(unit, false); e != nil {
		return e
	}
	fs, e := os.OpenRoot(n.root)
	if e != nil {
		return e
	}
	defer fs.Close()
	if e = fs.Remove(roleWantsDirectory + "/" + unit); e != nil {
		return e
	}
	d, e := fs.Open(roleWantsDirectory)
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}
