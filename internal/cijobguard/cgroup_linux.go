//go:build linux

package cijobguard

import (
	"context"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// Cgroup owns handles to one caller-selected, already-owned job subtree. It
// creates no directory and grants no migration/delegation authority.
type Cgroup struct {
	mu           sync.Mutex
	kill, events *os.File
}

// OpenCgroup borrows directory during this call. The caller must establish its
// exact lifecycle ownership and exclude the supervisor/other jobs beforehand.
// Files are opened relative to the descriptor without following child symlinks.
func OpenCgroup(directory *os.File) (*Cgroup, error) {
	if directory == nil {
		return nil, ErrCgroup
	}
	fd := int(directory.Fd())
	var stat unix.Stat_t
	var fs unix.Statfs_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != uint32(os.Geteuid()) || stat.Mode&0o022 != 0 || unix.Fstatfs(fd, &fs) != nil || fs.Type != unix.CGROUP2_SUPER_MAGIC {
		return nil, ErrCgroup
	}
	open := func(name string, flags int) (*os.File, error) {
		n, e := unix.Openat(fd, name, flags|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
		if e != nil {
			return nil, ErrCgroup
		}
		var s unix.Stat_t
		var f unix.Statfs_t
		if unix.Fstat(n, &s) != nil || s.Mode&unix.S_IFMT != unix.S_IFREG || s.Dev != stat.Dev || unix.Fstatfs(n, &f) != nil || f.Type != unix.CGROUP2_SUPER_MAGIC {
			unix.Close(n)
			return nil, ErrCgroup
		}
		return os.NewFile(uintptr(n), name), nil
	}
	kind, e := open("cgroup.type", unix.O_RDONLY)
	if e != nil {
		return nil, e
	}
	raw, e := io.ReadAll(io.LimitReader(kind, 128))
	_ = kind.Close()
	if e != nil || strings.TrimSpace(string(raw)) != "domain" {
		return nil, ErrCgroup
	}
	kill, e := open("cgroup.kill", unix.O_WRONLY)
	if e != nil {
		return nil, e
	}
	events, e := open("cgroup.events", unix.O_RDONLY)
	if e != nil {
		kill.Close()
		return nil, e
	}
	return &Cgroup{kill: kill, events: events}, nil
}

// Kill writes only the pinned subtree's kill handle and verifies populated=0.
// Cancellation or a failed write/read is an error, never evidence of cleanup.
// The caller must prevent new unrelated tasks being placed in this subtree.
func (c *Cgroup) Kill(ctx context.Context) error {
	if c == nil || ctx == nil {
		return ErrCgroup
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.kill == nil || c.events == nil || ctx.Err() != nil {
		return ErrCgroup
	}
	if n, e := unix.Write(int(c.kill.Fd()), []byte("1")); e != nil || n != 1 {
		return ErrCgroup
	}
	timer := time.NewTicker(10 * time.Millisecond)
	defer timer.Stop()
	for {
		if ctx.Err() != nil {
			return ErrCgroup
		}
		var b [512]byte
		n, e := c.events.ReadAt(b[:], 0)
		if e != nil && e != io.EOF || n == 0 || n == len(b) {
			return ErrCgroup
		}
		populated := ""
		for _, line := range strings.Split(string(b[:n]), "\n") {
			fields := strings.Fields(line)
			if len(fields) > 0 && fields[0] == "populated" {
				if populated != "" || len(fields) != 2 || (fields[1] != "0" && fields[1] != "1") {
					return ErrCgroup
				}
				populated = fields[1]
			}
		}
		if populated == "0" {
			return nil
		}
		if populated != "1" {
			return ErrCgroup
		}
		select {
		case <-ctx.Done():
			return ErrCgroup
		case <-timer.C:
		}
	}
}
func (c *Cgroup) Close() error {
	if c == nil {
		return ErrCgroup
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.kill == nil {
		return nil
	}
	a := c.kill.Close()
	b := c.events.Close()
	c.kill = nil
	c.events = nil
	if a != nil || b != nil {
		return ErrCgroup
	}
	return nil
}
