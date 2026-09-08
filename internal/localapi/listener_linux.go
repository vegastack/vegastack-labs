//go:build linux

package localapi

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"golang.org/x/sys/unix"
)

type fileIdentity struct {
	device uint64
	inode  uint64
	owner  uint32
	mode   uint32
	typeID uint32
}

type guardedListener struct {
	listener     *net.UnixListener
	lockFile     *os.File
	lockIdentity fileIdentity
	socket       fileIdentity
	profile      ListenConfig

	mu          sync.Mutex
	connections map[net.Conn]struct{}
	cleanupOnce sync.Once
	cleanupErr  error
}

func Listen(ctx context.Context, config ListenConfig) (Listener, error) {
	if err := ctx.Err(); err != nil {
		return nil, failure.New("INTERRUPTED", "control-service", false)
	}
	if config.Resolver == nil || config.Profile.SocketPath == "" {
		return nil, failure.New("INPUT_INVALID", "control-service", false)
	}
	if err := validateSocketParent(config); err != nil {
		return nil, err
	}
	lock, lockIdentity, err := acquireLock(config)
	if err != nil {
		return nil, err
	}
	keepLock := false
	defer func() {
		if !keepLock {
			_ = unix.Flock(int(lock.Fd()), unix.LOCK_UN)
			_ = lock.Close()
		}
	}()
	if err := removeProvenStaleSocket(config); err != nil {
		return nil, err
	}
	address := &net.UnixAddr{Name: config.Profile.SocketPath, Net: "unix"}
	listener, err := net.ListenUnix("unix", address)
	if err != nil {
		return nil, failure.New("STATE_CONFLICT", "control-service", false)
	}
	listener.SetUnlinkOnClose(false)
	createdIdentity, err := statIdentity(config.Profile.SocketPath)
	if err != nil || createdIdentity.typeID != unix.S_IFSOCK {
		_ = listener.Close()
		return nil, failure.New("INTEGRITY_FAILURE", "control-socket", false)
	}
	keepListener := false
	defer func() {
		if !keepListener {
			_ = listener.Close()
			_ = removeIfSameNode(config.Profile.SocketPath, createdIdentity)
		}
	}()
	gid := -1
	if config.Profile.SocketGroupGID != nil {
		gid = int(*config.Profile.SocketGroupGID)
	}
	if err := unix.Fchownat(unix.AT_FDCWD, config.Profile.SocketPath, int(config.Profile.SocketOwnerUID), gid, unix.AT_SYMLINK_NOFOLLOW); err != nil ||
		unix.Fchmodat(unix.AT_FDCWD, config.Profile.SocketPath, uint32(config.Profile.SocketMode.Perm()), unix.AT_SYMLINK_NOFOLLOW) != nil {
		return nil, failure.New("INTEGRITY_FAILURE", "control-socket", false)
	}
	socketIdentity, err := statIdentity(config.Profile.SocketPath)
	if err != nil || !socketIdentity.matchesSocket(config) {
		return nil, failure.New("INTEGRITY_FAILURE", "control-socket", false)
	}
	guarded := &guardedListener{
		listener: listener, lockFile: lock, lockIdentity: lockIdentity, socket: socketIdentity,
		profile: config, connections: make(map[net.Conn]struct{}),
	}
	if err := guarded.CheckPath(); err != nil {
		return nil, err
	}
	keepLock = true
	keepListener = true
	return guarded, nil
}

func validateSocketParent(config ListenConfig) error {
	parent := filepath.Dir(config.Profile.SocketPath)
	stat, err := statIdentity(parent)
	if err != nil || stat.typeID != unix.S_IFDIR || stat.owner != config.Profile.SocketOwnerUID || (stat.mode != 0o700 && stat.mode != 0o750) {
		return failure.New("INTEGRITY_FAILURE", "control-socket-parent", false)
	}
	return nil
}

func acquireLock(config ListenConfig) (*os.File, fileIdentity, error) {
	path := config.Profile.SocketPath + ".lock"
	flags := unix.O_RDWR | unix.O_CLOEXEC | unix.O_NOFOLLOW
	descriptor, err := unix.Open(path, flags|unix.O_CREAT|unix.O_EXCL, 0o600)
	if errors.Is(err, unix.EEXIST) {
		descriptor, err = unix.Open(path, flags, 0)
	}
	if err != nil {
		return nil, fileIdentity{}, failure.New("INTEGRITY_FAILURE", "control-service-lock", false)
	}
	file := os.NewFile(uintptr(descriptor), "control-service-lock")
	if file == nil {
		_ = unix.Close(descriptor)
		return nil, fileIdentity{}, failure.New("INTEGRITY_FAILURE", "control-service-lock", false)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(descriptor, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Uid != config.Profile.SocketOwnerUID || stat.Mode&0o777 != 0o600 {
		_ = file.Close()
		return nil, fileIdentity{}, failure.New("INTEGRITY_FAILURE", "control-service-lock", false)
	}
	if err := unix.Flock(descriptor, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, fileIdentity{}, failure.New("STATE_CONFLICT", "control-service", false)
		}
		return nil, fileIdentity{}, failure.New("INTEGRITY_FAILURE", "control-service-lock", false)
	}
	identity := identityFromStat(stat)
	pathIdentity, pathErr := statIdentity(path)
	if pathErr != nil || pathIdentity != identity {
		_ = unix.Flock(descriptor, unix.LOCK_UN)
		_ = file.Close()
		return nil, fileIdentity{}, failure.New("INTEGRITY_FAILURE", "control-service-lock", false)
	}
	return file, identity, nil
}

func removeProvenStaleSocket(config ListenConfig) error {
	first, err := statIdentity(config.Profile.SocketPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !first.matchesSocket(config) {
		return failure.New("INTEGRITY_FAILURE", "control-socket", false)
	}
	second, err := statIdentity(config.Profile.SocketPath)
	if err != nil || second != first {
		return failure.New("INTEGRITY_FAILURE", "control-socket", false)
	}
	if err := unix.Unlink(config.Profile.SocketPath); err != nil {
		return failure.New("INTEGRITY_FAILURE", "control-socket", false)
	}
	return nil
}

func (listener *guardedListener) Accept() (net.Conn, error) {
	for {
		if err := listener.CheckPath(); err != nil {
			_ = listener.listener.Close()
			return nil, err
		}
		connection, err := listener.listener.AcceptUnix()
		if err != nil {
			return nil, err
		}
		if err := listener.CheckPath(); err != nil {
			_ = connection.Close()
			_ = listener.listener.Close()
			return nil, err
		}
		peer, err := peerCredentials(connection)
		if err != nil {
			_ = connection.Close()
			continue
		}
		principal, err := listener.profile.Resolver.ResolveLocalPeer(context.Background(), peer)
		if err != nil {
			_ = connection.Close()
			continue
		}
		listener.mu.Lock()
		listener.connections[connection] = struct{}{}
		listener.mu.Unlock()
		return newAuthenticatedConn(connection, principal, func() {
			listener.mu.Lock()
			delete(listener.connections, connection)
			listener.mu.Unlock()
		}), nil
	}
}

func peerCredentials(connection *net.UnixConn) (identity.LocalPeer, error) {
	raw, err := connection.SyscallConn()
	if err != nil {
		return identity.LocalPeer{}, err
	}
	var credentials *unix.Ucred
	var controlErr error
	if err := raw.Control(func(fd uintptr) {
		credentials, controlErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return identity.LocalPeer{}, err
	}
	if controlErr != nil || credentials == nil {
		return identity.LocalPeer{}, controlErr
	}
	return identity.LocalPeer{PID: credentials.Pid, UID: credentials.Uid, GID: credentials.Gid}, nil
}

func (listener *guardedListener) Close() error {
	return listener.listener.Close()
}

func (listener *guardedListener) Addr() net.Addr {
	return listener.listener.Addr()
}

func (listener *guardedListener) CheckPath() error {
	lockIdentity, lockErr := statIdentity(listener.profile.Profile.SocketPath + ".lock")
	socketIdentity, socketErr := statIdentity(listener.profile.Profile.SocketPath)
	if lockErr != nil || socketErr != nil || lockIdentity != listener.lockIdentity || socketIdentity != listener.socket || !socketIdentity.matchesSocket(listener.profile) {
		return failure.New("INTEGRITY_FAILURE", "control-socket", false)
	}
	return nil
}

func (listener *guardedListener) Cleanup() error {
	listener.cleanupOnce.Do(func() {
		if err := listener.listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			listener.cleanupErr = failure.New("INTEGRITY_FAILURE", "control-socket", false)
		}
		listener.mu.Lock()
		for connection := range listener.connections {
			_ = connection.Close()
		}
		listener.connections = make(map[net.Conn]struct{})
		listener.mu.Unlock()
		if err := removeIfSameSocket(listener.profile.Profile.SocketPath, listener.socket, true); err != nil && listener.cleanupErr == nil {
			listener.cleanupErr = err
		}
		if err := unix.Flock(int(listener.lockFile.Fd()), unix.LOCK_UN); err != nil && listener.cleanupErr == nil {
			listener.cleanupErr = failure.New("INTEGRITY_FAILURE", "control-service-lock", false)
		}
		if err := listener.lockFile.Close(); err != nil && listener.cleanupErr == nil {
			listener.cleanupErr = failure.New("INTEGRITY_FAILURE", "control-service-lock", false)
		}
	})
	return listener.cleanupErr
}

func removeIfSameSocket(path string, expected fileIdentity, requireMatch bool) error {
	actual, err := statIdentity(path)
	if errors.Is(err, os.ErrNotExist) && !requireMatch {
		return nil
	}
	if err != nil || (requireMatch && actual != expected) || actual.typeID != unix.S_IFSOCK {
		return failure.New("INTEGRITY_FAILURE", "control-socket", false)
	}
	if err := unix.Unlink(path); err != nil {
		return failure.New("INTEGRITY_FAILURE", "control-socket", false)
	}
	return nil
}

func removeIfSameNode(path string, expected fileIdentity) error {
	actual, err := statIdentity(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || actual.device != expected.device || actual.inode != expected.inode || actual.typeID != unix.S_IFSOCK {
		return failure.New("INTEGRITY_FAILURE", "control-socket", false)
	}
	if err := unix.Unlink(path); err != nil {
		return failure.New("INTEGRITY_FAILURE", "control-socket", false)
	}
	return nil
}

func statIdentity(path string) (fileIdentity, error) {
	var stat unix.Stat_t
	if err := unix.Lstat(path, &stat); err != nil {
		return fileIdentity{}, err
	}
	return identityFromStat(stat), nil
}

func identityFromStat(stat unix.Stat_t) fileIdentity {
	return fileIdentity{device: stat.Dev, inode: stat.Ino, owner: stat.Uid, mode: stat.Mode & 0o777, typeID: stat.Mode & unix.S_IFMT}
}

func (identity fileIdentity) matchesSocket(config ListenConfig) bool {
	return identity.typeID == unix.S_IFSOCK && identity.owner == config.Profile.SocketOwnerUID && identity.mode == uint32(config.Profile.SocketMode.Perm())
}
