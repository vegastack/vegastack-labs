//go:build linux

package linuxrole

import (
	"bytes"
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"path"
	"strconv"
	"strings"
)

// RecheckNativeRecoveryDestination is the service-UID final preimage check.
// Physical machine identity stays bound to the root parent's sealed observation.
func RecheckNativeRecoveryDestination(ctx context.Context, in generated.LinuxRoleInput, uid, gid int64) error {
	if ctx.Err() != nil || ValidateInput(in) != nil || in.RoleID != "control" || int64(os.Getuid()) != uid || int64(os.Getgid()) != gid || len(in.Accounts) != 1 || in.Accounts[0].UID != uid || in.Accounts[0].GID != gid {
		return errNative
	}
	n := NewNativeRuntime(in.ProfileLock.ExecutableVersion).(*nativeRuntime)
	for _, a := range in.Accounts {
		if _, e := n.account(ctx, a, false); e != nil {
			return e
		}
	}
	root, e := os.OpenRoot("/")
	if e != nil {
		return e
	}
	defer root.Close()
	dirs := map[string]generated.LinuxRoleDirectory{}
	for _, d := range in.Directories {
		dirs[strings.TrimPrefix(DirectoryPath(in.RoleID, d.Selector), "/")] = d
	}
	inspect := func(p string, owner int64, limit int64) ([]byte, error) {
		parts := strings.Split(p, "/")
		for i := range parts {
			name := strings.Join(parts[:i+1], "/")
			f, e := root.OpenFile(name, os.O_RDONLY|unix.O_NOFOLLOW, 0)
			if e != nil {
				return nil, e
			}
			var st unix.Stat_t
			e = unix.Fstat(int(f.Fd()), &st)
			wantOwner := int64(0)
			if d, ok := dirs[name]; ok {
				wantOwner = d.UID
				mode, pe := strconv.ParseUint(d.Mode, 8, 32)
				if pe != nil || st.Mode&0777 != uint32(mode) || int64(st.Gid) != d.GID {
					f.Close()
					return nil, errNative
				}
			}
			if i == len(parts)-1 {
				wantOwner = owner
			}
			if e != nil || int64(st.Uid) != wantOwner || st.Mode&0022 != 0 {
				f.Close()
				return nil, errNative
			}
			if i < len(parts)-1 || limit == 0 {
				f.Close()
				if st.Mode&unix.S_IFMT != unix.S_IFDIR {
					return nil, errNative
				}
				continue
			}
			if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Size < 0 || st.Size > limit {
				f.Close()
				return nil, errNative
			}
			raw, e := io.ReadAll(io.LimitReader(f, limit+1))
			f.Close()
			if e != nil || int64(len(raw)) > limit {
				return nil, errNative
			}
			return raw, nil
		}
		return nil, nil
	}
	for p, d := range dirs {
		if _, e = inspect(p, d.UID, 0); e != nil {
			return e
		}
	}
	for p, want := range DesiredFiles(in) {
		raw, e := inspect(path.Clean(p), 0, 65536)
		if e != nil || !bytes.Equal(raw, want) {
			return errNative
		}
	}
	executable, e := inspect("usr/local/bin/vsk-labs", 0, 128<<20)
	if e != nil || hostaction.BytesDigest(executable) != in.ExecutableDigest {
		return errNative
	}
	cfg, e := inspect("etc/vsk-labs/control/server.json", uid, 65536)
	if e != nil || hostaction.BytesDigest(cfg) != in.ConfigDigest {
		return errNative
	}
	if e = n.unitOverrides(UnitName(in.RoleID)); e != nil {
		return e
	}
	raw, e := n.run(ctx, "/usr/bin/systemctl", resourceArgs(in))
	if e != nil {
		return e
	}
	p := parseProperties(raw)
	if p["ActiveState"] != "inactive" || p["MainPID"] != "0" || p["User"] != strconv.FormatInt(uid, 10) || p["Group"] != strconv.FormatInt(gid, 10) || p["FragmentPath"] != "/etc/systemd/system/vsk-labs.service" || p["DropInPaths"] != "" {
		return errNative
	}
	return nil
}
