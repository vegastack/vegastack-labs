//go:build linux

package backup

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// maxObjectBytes bounds any single object body the routine writer may create.
const maxObjectBytes = 2 << 30 // 2 GiB
const maxRepositoryConfigBytes = 64 << 10

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
	// The only query restic sends is ?create=true on repository initialization.
	create := false
	if r.URL.RawQuery != "" {
		if r.URL.RawQuery != "create=true" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		create = true
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
	// Repository-level requests (create the layout, or list a type directory)
	// are classified before single-object parsing.
	if repositoryRequest, ok := parseRepositoryRequest(r.URL.Path, server.repositoryID); ok {
		switch {
		case repositoryRequest.isRepositoryRoot && create && r.Method == http.MethodPost:
			server.handleRepositoryCreate(w)
		case repositoryRequest.isList && !create && r.Method == http.MethodGet:
			server.handleList(w, repositoryRequest)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
		return
	}
	request, ok := parseObjectPath(r.URL.Path, server.repositoryID)
	if !ok || create {
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

// handleRepositoryCreate creates the repository-format-v2 object-type directories
// under the (already validated) repository root. It never overwrites an existing
// retained object; the config object itself is written separately by the client.
func (server *RESTServer) handleRepositoryCreate(w http.ResponseWriter) {
	rootDescriptor, err := server.openRepositoryRoot()
	if err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	defer unix.Close(rootDescriptor)
	for _, objectType := range []string{"keys", "data", "index", "snapshots", "locks"} {
		if err := unix.Mkdirat(rootDescriptor, objectType, 0o700); err != nil && !errors.Is(err, unix.EEXIST) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
	}
	_ = unix.Fsync(rootDescriptor)
	w.WriteHeader(http.StatusOK)
}

// handleList returns the restic REST v2 object listing for one type directory:
// a JSON array of {name,size}. It enumerates through the validated directory
// descriptor and reports only service-owned regular files.
func (server *RESTServer) handleList(w http.ResponseWriter, request objectRequest) {
	typeDescriptor, err := server.openTypeDir(request.objectType, false)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			http.Error(w, "not found", http.StatusNotFound)
		} else {
			http.Error(w, "forbidden", http.StatusForbidden)
		}
		return
	}
	// os.NewFile takes ownership of the descriptor; closing the directory below
	// closes it, so we must not also unix.Close it.
	directory := os.NewFile(uintptr(typeDescriptor), request.objectType)
	if directory == nil {
		_ = unix.Close(typeDescriptor)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	defer directory.Close()
	names, readErr := directory.Readdirnames(-1)
	if readErr != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	type entry struct {
		Name string `json:"name"`
		Size int64  `json:"size"`
	}
	entries := make([]entry, 0, len(names))
	for _, name := range names {
		if !validObjectName(name) {
			continue
		}
		descriptor, err := unix.Openat(typeDescriptor, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			continue
		}
		var stat unix.Stat_t
		if unix.Fstat(descriptor, &stat) == nil && stat.Mode&unix.S_IFMT == unix.S_IFREG && stat.Nlink == 1 && stat.Uid == server.expectedUID && isLocalDescriptor(descriptor) {
			entries = append(entries, entry{Name: name, Size: stat.Size})
		}
		_ = unix.Close(descriptor)
	}
	body, err := json.Marshal(entries)
	if err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "application/vnd.x.restic.rest.v2")
	_, _ = w.Write(body)
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
	// restic 0.19.1 reads encrypted packs by byte range. ServeContent supplies
	// exact Content-Length/Content-Range and 416 handling from this verified FD.
	http.ServeContent(w, r, request.name, time.Time{}, file)
}

func (server *RESTServer) handleHead(w http.ResponseWriter, request objectRequest) {
	descriptor, err := server.openObject(request, false)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	var stat unix.Stat_t
	if unix.Fstat(descriptor, &stat) != nil {
		_ = unix.Close(descriptor)
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	_ = unix.Close(descriptor)
	w.Header().Set("Content-Length", strconv.FormatInt(stat.Size, 10))
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
	if !server.mayDeleteLock(request.name) {
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

// mayDeleteLock allows removing only a lock this exact lease session created.
// A foreign lock — including a concurrent verifier's live lock — is never deleted
// through the routine writer, so a long-running live lock cannot be removed here.
// Stale-orphan reclamation is a separate, explicitly-proven recovery operation,
// not a time-threshold guess on the write path.
func (server *RESTServer) mayDeleteLock(name string) bool {
	server.mu.Lock()
	defer server.mu.Unlock()
	_, own := server.ownLocks[name]
	return own
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

// RepositoryFormat reads the exact retained config through the same guarded
// object open used by REST GET. A malformed, oversized, or unsupported config
// cannot be treated as a v2 repository before a backup effect.
func (server *RESTServer) RepositoryFormat() (int, error) {
	request := objectRequest{objectType: "config", name: "config", isConfig: true}
	descriptor, err := server.openObject(request, false)
	if err != nil {
		return 0, err
	}
	file := os.NewFile(uintptr(descriptor), "restic-config")
	defer file.Close()
	var config struct {
		Version int    `json:"version"`
		ID      string `json:"id"`
	}
	decoder := json.NewDecoder(io.LimitReader(file, maxRepositoryConfigBytes+1))
	if err := decoder.Decode(&config); err != nil || config.Version != 2 || !validObjectName(config.ID) {
		return 0, errors.New("unsupported repository config")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return 0, errors.New("malformed repository config")
	}
	if offset, err := file.Seek(0, io.SeekCurrent); err != nil || offset > maxRepositoryConfigBytes {
		return 0, errors.New("oversized repository config")
	}
	return config.Version, nil
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
