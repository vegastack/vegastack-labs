//go:build linux

package backup

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// maxObjectBytes bounds any single object body the routine writer may create.
const maxObjectBytes = 2 << 30 // 2 GiB

// RESTServer is the same-process, lease-bound restic REST object boundary. It
// serves exactly one repository for exactly one exact writer lease over a Unix
// socket. Its routine writer may create new payload objects and create/remove
// mutable locks only; it can never overwrite or delete retained config, keys,
// data, index or snapshots objects, follow a symlink, cross a hardlink, write a
// non-regular file, or accept a peer other than the service owner. A lock-free
// mode is never offered: locking is always enforced by the client, never disabled.
type RESTServer struct {
	root         string
	repositoryID string
	expectedUID  uint32
	lease        WriterLease
	verifier     LeaseVerifier
	clock        func() time.Time
	staleAfter   time.Duration
	mu           sync.Mutex
	ownLocks     map[string]struct{}
}

// NewRESTServer builds a REST boundary bound to one resolved repository root and
// one exact writer lease.
func NewRESTServer(root string, expectedUID uint32, lease WriterLease, verifier LeaseVerifier, clock func() time.Time) (*RESTServer, error) {
	if root == "" || lease.RepositoryID == "" || verifier == nil {
		return nil, errors.New("backup rest server misconfigured")
	}
	if clock == nil {
		clock = time.Now
	}
	return &RESTServer{
		root:         root,
		repositoryID: lease.RepositoryID,
		expectedUID:  expectedUID,
		lease:        lease,
		verifier:     verifier,
		clock:        clock,
		staleAfter:   30 * time.Minute,
		ownLocks:     map[string]struct{}{},
	}, nil
}

// Serve accepts only service-owner peers on the listener and serves the guarded
// object boundary until ctx is cancelled.
func (server *RESTServer) Serve(ctx context.Context, listener net.Listener) error {
	guarded := &peerCheckedListener{Listener: listener, expectedUID: server.expectedUID}
	httpServer := &http.Server{
		Handler:           server,
		ReadHeaderTimeout: 30 * time.Second,
	}
	go func() {
		<-ctx.Done()
		_ = httpServer.Close()
	}()
	err := httpServer.Serve(guarded)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (server *RESTServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	// Every request re-verifies the exact writer lease and its deadline.
	if err := server.verifier.VerifyWriterLease(server.lease, server.clock()); err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if !server.clock().Before(server.lease.MaximumExpiresAt) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	request, ok := parseObjectPath(r.URL.Path, server.repositoryID)
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	switch r.Method {
	case http.MethodGet:
		server.handleGet(w, r, request)
	case http.MethodHead:
		server.handleHead(w, request)
	case http.MethodPost, http.MethodPut:
		server.handleCreate(w, r, request)
	case http.MethodDelete:
		server.handleDelete(w, request)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (server *RESTServer) handleGet(w http.ResponseWriter, r *http.Request, request objectRequest) {
	descriptor, err := server.openObject(request, false)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	file := os.NewFile(uintptr(descriptor), "restic-object")
	if file == nil {
		_ = unix.Close(descriptor)
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	defer file.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = io.Copy(w, file)
}

func (server *RESTServer) handleHead(w http.ResponseWriter, request objectRequest) {
	descriptor, err := server.openObject(request, false)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	_ = unix.Close(descriptor)
	w.WriteHeader(http.StatusOK)
}

func (server *RESTServer) handleCreate(w http.ResponseWriter, r *http.Request, request objectRequest) {
	typeDescriptor, err := server.openTypeDir(request.objectType, true)
	if err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	defer unix.Close(typeDescriptor)
	// Atomic create-without-replace: an existing retained object is immutable, and
	// an existing lock cannot be silently rewritten either.
	descriptor, err := unix.Openat(typeDescriptor, request.name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		if errors.Is(err, unix.EEXIST) {
			http.Error(w, "conflict", http.StatusConflict)
			return
		}
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	file := os.NewFile(uintptr(descriptor), "restic-object")
	if file == nil {
		_ = unix.Close(descriptor)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	written, copyErr := io.Copy(file, io.LimitReader(r.Body, maxObjectBytes+1))
	syncErr := file.Sync()
	closeErr := file.Close()
	if copyErr != nil || written > maxObjectBytes || syncErr != nil || closeErr != nil {
		_ = unix.Unlinkat(typeDescriptor, request.name, 0)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := unix.Fsync(typeDescriptor); err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if request.isLock {
		server.mu.Lock()
		server.ownLocks[request.name] = struct{}{}
		server.mu.Unlock()
	}
	w.WriteHeader(http.StatusOK)
}

func (server *RESTServer) handleDelete(w http.ResponseWriter, request objectRequest) {
	if request.retained {
		// config, keys, data, index and snapshots are immutable once created.
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if !request.isLock {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	typeDescriptor, err := server.openTypeDir(request.objectType, false)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	defer unix.Close(typeDescriptor)
	if !server.mayDeleteLock(typeDescriptor, request.name) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := unix.Unlinkat(typeDescriptor, request.name, 0); err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	_ = unix.Fsync(typeDescriptor)
	server.mu.Lock()
	delete(server.ownLocks, request.name)
	server.mu.Unlock()
	w.WriteHeader(http.StatusOK)
}

// mayDeleteLock allows removing only a lock this lease session created (its own
// writer lock) or a proven stale orphan older than the stale threshold. A live
// lock held by another session (for example a concurrent verifier) is preserved.
func (server *RESTServer) mayDeleteLock(typeDescriptor int, name string) bool {
	server.mu.Lock()
	_, own := server.ownLocks[name]
	server.mu.Unlock()
	if own {
		return true
	}
	descriptor, err := unix.Openat(typeDescriptor, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return false
	}
	defer unix.Close(descriptor)
	var stat unix.Stat_t
	if unix.Fstat(descriptor, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != server.expectedUID {
		return false
	}
	modified := time.Unix(stat.Mtim.Sec, stat.Mtim.Nsec)
	return server.clock().Sub(modified) > server.staleAfter
}

// openObject opens one existing object read-only under the repository root using
// FD-relative, symlink-refusing access, and confirms it is a service-owned
// regular file with a single hardlink on a supported local filesystem.
func (server *RESTServer) openObject(request objectRequest, _ bool) (int, error) {
	typeDescriptor, err := server.openTypeDir(request.objectType, false)
	if err != nil {
		return -1, err
	}
	defer unix.Close(typeDescriptor)
	descriptor, err := unix.Openat(typeDescriptor, request.name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, err
	}
	var stat unix.Stat_t
	if unix.Fstat(descriptor, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Uid != server.expectedUID || !isLocalDescriptor(descriptor) {
		_ = unix.Close(descriptor)
		return -1, errors.New("unsafe object")
	}
	return descriptor, nil
}

// openTypeDir opens (optionally creating) the object-type subdirectory of the
// repository root using FD-relative, symlink-refusing access. The config object
// lives directly under the root, so its "type directory" is the root itself.
func (server *RESTServer) openTypeDir(objectType string, create bool) (int, error) {
	rootDescriptor, err := server.openRepositoryRoot()
	if err != nil {
		return -1, err
	}
	if objectType == "config" {
		return rootDescriptor, nil
	}
	defer unix.Close(rootDescriptor)
	descriptor, err := unix.Openat(rootDescriptor, objectType, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err == nil {
		if err := validateOwnedDirectoryDescriptor(descriptor, server.expectedUID); err != nil {
			_ = unix.Close(descriptor)
			return -1, err
		}
		return descriptor, nil
	}
	if !create || !errors.Is(err, unix.ENOENT) {
		return -1, err
	}
	if err := unix.Mkdirat(rootDescriptor, objectType, 0o700); err != nil {
		return -1, err
	}
	if err := unix.Fsync(rootDescriptor); err != nil {
		return -1, err
	}
	descriptor, err = unix.Openat(rootDescriptor, objectType, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, err
	}
	if err := validateOwnedDirectoryDescriptor(descriptor, server.expectedUID); err != nil {
		_ = unix.Close(descriptor)
		return -1, err
	}
	return descriptor, nil
}

func (server *RESTServer) openRepositoryRoot() (int, error) {
	descriptor, err := unix.Openat2(unix.AT_FDCWD, server.root, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return -1, err
	}
	if err := validateOwnedDirectoryDescriptor(descriptor, server.expectedUID); err != nil {
		_ = unix.Close(descriptor)
		return -1, err
	}
	return descriptor, nil
}

// peerCheckedListener admits only local peers whose effective UID is the service
// owner, closing every other connection before it reaches the HTTP handler.
type peerCheckedListener struct {
	net.Listener
	expectedUID uint32
}

func (listener *peerCheckedListener) Accept() (net.Conn, error) {
	for {
		conn, err := listener.Listener.Accept()
		if err != nil {
			return nil, err
		}
		unixConn, ok := conn.(*net.UnixConn)
		if !ok {
			_ = conn.Close()
			continue
		}
		if !peerIsOwner(unixConn, listener.expectedUID) {
			_ = conn.Close()
			continue
		}
		return conn, nil
	}
}

func peerIsOwner(conn *net.UnixConn, expectedUID uint32) bool {
	raw, err := conn.SyscallConn()
	if err != nil {
		return false
	}
	var credentials *unix.Ucred
	var credErr error
	if controlErr := raw.Control(func(fd uintptr) {
		credentials, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); controlErr != nil {
		return false
	}
	return credErr == nil && credentials != nil && credentials.Uid == expectedUID
}
