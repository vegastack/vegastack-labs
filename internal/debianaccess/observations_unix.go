//go:build linux || darwin

package debianaccess

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
	"golang.org/x/sys/unix"
	"io"
	"net"
	"os"
	"strings"
)

type interfaceFact struct {
	Name      string
	Index     int64
	Addresses []string
	Loopback  bool
}

func nativeInterfaceFacts() ([]interfaceFact, error) {
	list, e := net.Interfaces()
	if e != nil {
		return nil, e
	}
	facts := []interfaceFact{}
	for _, i := range list {
		addresses, e := i.Addrs()
		if e != nil {
			return nil, e
		}
		f := interfaceFact{Name: i.Name, Index: int64(i.Index), Loopback: i.Flags&net.FlagLoopback != 0}
		for _, a := range addresses {
			ip, _, e := net.ParseCIDR(a.String())
			if e != nil {
				return nil, errAccess
			}
			f.Addresses = append(f.Addresses, ip.String())
		}
		facts = append(facts, f)
	}
	return facts, nil
}
func (n *nativeRuntime) inspectInterfaces(in generated.DebianAccessInput) error {
	observe := n.interfaces
	if observe == nil {
		observe = nativeInterfaceFacts
	}
	facts, e := observe()
	if e != nil {
		return e
	}
	declared := map[string]generated.AccessInterface{}
	for _, i := range in.Interfaces {
		declared[i.Name] = i
	}
	seen := map[string]bool{}
	for _, f := range facts {
		if f.Loopback {
			continue
		}
		i, ok := declared[f.Name]
		if !ok {
			if len(f.Addresses) > 0 {
				return errAccess
			}
			continue
		}
		if i.Index != f.Index {
			return errAccess
		}
		want := map[string]bool{}
		for _, a := range i.Addresses {
			want[a] = true
		}
		for _, a := range f.Addresses {
			if !want[a] || strings.Contains(a, ":") && !i.IPv6Enabled {
				return errAccess
			}
			delete(want, a)
		}
		if len(want) != 0 {
			return errAccess
		}
		seen[i.Name] = true
	}
	if len(seen) != len(declared) {
		return errAccess
	}
	return nil
}
func fileOwnership(f *os.File) (uint32, uint32, error) {
	var st unix.Stat_t
	if e := unix.Fstat(int(f.Fd()), &st); e != nil {
		return 0, 0, e
	}
	return st.Uid, st.Gid, nil
}
func (n *nativeRuntime) inspectHome(a generated.AccessAccount, accountExists bool) error {
	fs, e := os.OpenRoot(n.root)
	if e != nil {
		return e
	}
	defer fs.Close()
	home := strings.TrimPrefix(a.Home, "/")
	file, e := fs.OpenFile(home, os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if !accountExists {
		if !os.IsNotExist(e) {
			if file != nil {
				file.Close()
			}
			return errAccess
		}
		return nil
	}
	if e != nil {
		return e
	}
	defer file.Close()
	info, e := file.Stat()
	if e != nil || !info.IsDir() || info.Mode().Perm()&0022 != 0 {
		return errAccess
	}
	observe := n.homeOwnership
	if observe == nil {
		observe = fileOwnership
	}
	uid, gid, e := observe(file)
	if e != nil || int64(uid) != a.UID || int64(gid) != a.GID {
		return errAccess
	}
	return nil
}

func (n *nativeRuntime) readUserAuthorizedKeys(a generated.AccessAccount) ([]byte, error) {
	fs, e := os.OpenRoot(n.root)
	if e != nil {
		return nil, e
	}
	defer fs.Close()
	p := strings.TrimPrefix(a.Home, "/") + "/.ssh/authorized_keys"
	parts := strings.Split(p, "/")
	for i := range parts {
		component := strings.Join(parts[:i+1], "/")
		f, e := fs.OpenFile(component, os.O_RDONLY|unix.O_NOFOLLOW, 0)
		if e != nil {
			return nil, e
		}
		var st unix.Stat_t
		e = unix.Fstat(int(f.Fd()), &st)
		if e != nil || st.Mode&0022 != 0 || (st.Uid != uint32(os.Geteuid()) && int64(st.Uid) != a.UID) {
			f.Close()
			return nil, errAccess
		}
		if i < len(parts)-1 {
			if st.Mode&unix.S_IFMT != unix.S_IFDIR {
				f.Close()
				return nil, errAccess
			}
			f.Close()
			continue
		}
		if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Size > 32768 {
			f.Close()
			return nil, errAccess
		}
		b, e := io.ReadAll(io.LimitReader(f, 32769))
		f.Close()
		return b, e
	}
	return nil, errAccess
}
