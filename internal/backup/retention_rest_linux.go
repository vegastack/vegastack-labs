//go:build linux

package backup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

// RetentionLease is a bounded, separately authorized session. It cannot be
// converted from the routine backup writer or point-bound verifier lease.
type RetentionLease struct {
	LeaseID, RepositoryID          string
	RecoveryEpoch                  int64
	MaximumExpiresAt               time.Time
	MaxMutations, MaxMutationBytes int64
	PlannedSnapshotIDs             []string
}

type RetentionLeaseVerifier interface {
	VerifyRetentionLease(RetentionLease, time.Time) error
}

// RetainedMutationAttempt is written durably before any retained object is
// removed from restic's visible namespace. It contains no secret material.
type RetainedMutationAttempt struct {
	LeaseID, RepositoryID, MutationKind, ObjectType, ObjectName, Digest string
	Bytes, RecoveryEpoch                                                int64
}

type RetainedMutationOutcome struct {
	LeaseID, ObjectType, ObjectName, QuarantineName string
	Status                                          string
}

type RetainedMutationJournal interface {
	BeginRetainedMutation(context.Context, RetainedMutationAttempt) error
	FinishRetainedMutation(context.Context, RetainedMutationOutcome) error
}

// NewRetentionRESTServer adds a distinct role that can hide retained objects
// only by journaling and renaming their exact inode into a same-filesystem,
// owner-only quarantine. No physical deletion path is exposed here.
func NewRetentionRESTServer(root, quarantine string, expectedUID uint32, lease RetentionLease, verifier RetentionLeaseVerifier, journal RetainedMutationJournal, clock func() time.Time) (*RESTServer, error) {
	if root == "" || quarantine == "" || filepath.Dir(root) != filepath.Dir(quarantine) ||
		lease.LeaseID == "" || lease.RepositoryID == "" || lease.RecoveryEpoch < 0 || lease.MaximumExpiresAt.IsZero() ||
		lease.MaxMutations < 1 || lease.MaxMutationBytes < 1 || verifier == nil || journal == nil {
		return nil, errors.New("retention rest server misconfigured")
	}
	if clock == nil {
		clock = time.Now
	}
	server := &RESTServer{root: root, repositoryID: lease.RepositoryID, expectedUID: expectedUID,
		retentionLease: &lease, retentionVerifier: verifier, retentionJournal: journal, quarantineRoot: quarantine,
		clock: clock, ownLocks: map[string]struct{}{}}
	rootFD, err := server.openRepositoryRoot()
	if err != nil {
		return nil, fmt.Errorf("repository root: %w", err)
	}
	defer unix.Close(rootFD)
	parentFD, err := unix.Openat2(unix.AT_FDCWD, filepath.Dir(quarantine), &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return nil, err
	}
	defer unix.Close(parentFD)
	if err := validateOwnedDirectoryDescriptor(parentFD, expectedUID); err != nil {
		return nil, fmt.Errorf("quarantine parent: %w", err)
	}
	if err := unix.Mkdirat(parentFD, filepath.Base(quarantine), 0o700); err != nil {
		return nil, err
	}
	if err := unix.Fsync(parentFD); err != nil {
		return nil, err
	}
	quarantineFD, err := server.openQuarantineRoot()
	if err != nil {
		return nil, fmt.Errorf("quarantine root: %w", err)
	}
	defer unix.Close(quarantineFD)
	var rootStat, quarantineStat unix.Stat_t
	if unix.Fstat(rootFD, &rootStat) != nil || unix.Fstat(quarantineFD, &quarantineStat) != nil || rootStat.Dev != quarantineStat.Dev {
		return nil, errors.New("retention quarantine must share repository filesystem")
	}
	return server, nil
}

func (server *RESTServer) openQuarantineRoot() (int, error) {
	fd, err := unix.Openat2(unix.AT_FDCWD, server.quarantineRoot, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return -1, err
	}
	if err := validateOwnedDirectoryDescriptor(fd, server.expectedUID); err != nil {
		unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

func (server *RESTServer) openQuarantineTypeDir(objectType string) (int, error) {
	rootFD, err := server.openQuarantineRoot()
	if err != nil {
		return -1, err
	}
	defer unix.Close(rootFD)
	if objectType == "config" {
		return -1, errors.New("retention cannot remove repository config")
	}
	if err := unix.Mkdirat(rootFD, objectType, 0o700); err != nil && !errors.Is(err, unix.EEXIST) {
		return -1, err
	}
	if err := unix.Fsync(rootFD); err != nil {
		return -1, err
	}
	fd, err := unix.Openat(rootFD, objectType, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, err
	}
	if err := validateOwnedDirectoryDescriptor(fd, server.expectedUID); err != nil {
		unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

func (server *RESTServer) openStagingTypeDir(objectType string) (int, error) {
	rootFD, err := server.openQuarantineRoot()
	if err != nil {
		return -1, err
	}
	defer unix.Close(rootFD)
	if err := unix.Mkdirat(rootFD, "staging", 0o700); err != nil && !errors.Is(err, unix.EEXIST) {
		return -1, err
	}
	if err := unix.Fsync(rootFD); err != nil {
		return -1, err
	}
	stagingFD, err := unix.Openat(rootFD, "staging", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, err
	}
	defer unix.Close(stagingFD)
	if err := validateOwnedDirectoryDescriptor(stagingFD, server.expectedUID); err != nil {
		return -1, err
	}
	if err := unix.Mkdirat(stagingFD, objectType, 0o700); err != nil && !errors.Is(err, unix.EEXIST) {
		return -1, err
	}
	if err := unix.Fsync(stagingFD); err != nil {
		return -1, err
	}
	typeFD, err := unix.Openat(stagingFD, objectType, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, err
	}
	if err := validateOwnedDirectoryDescriptor(typeFD, server.expectedUID); err != nil {
		unix.Close(typeFD)
		return -1, err
	}
	return typeFD, nil
}

func (server *RESTServer) handleRetainedCreate(w http.ResponseWriter, r *http.Request, object objectRequest) {
	if (r.Method != http.MethodPost && r.Method != http.MethodPut) || (object.objectType != "data" && object.objectType != "index" && object.objectType != "locks") || r.Body == nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	if server.retentionMutations >= server.retentionLease.MaxMutations || server.retentionBytes >= server.retentionLease.MaxMutationBytes {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	stagingFD, err := server.openStagingTypeDir(object.objectType)
	if err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	defer unix.Close(stagingFD)
	fd, err := unix.Openat(stagingFD, object.name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		http.Error(w, "conflict", http.StatusConflict)
		return
	}
	file := os.NewFile(uintptr(fd), object.name)
	if file == nil {
		unix.Close(fd)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	hasher := sha256.New()
	limit := server.retentionLease.MaxMutationBytes - server.retentionBytes
	if limit > maxObjectBytes {
		limit = maxObjectBytes
	}
	bytes, copyErr := io.Copy(io.MultiWriter(file, hasher), io.LimitReader(r.Body, limit+1))
	syncErr, closeErr := file.Sync(), file.Close()
	if copyErr != nil || syncErr != nil || closeErr != nil || bytes < 1 || bytes > limit || unix.Fsync(stagingFD) != nil {
		http.Error(w, "uncertain", http.StatusServiceUnavailable)
		return
	}
	attempt := RetainedMutationAttempt{LeaseID: server.retentionLease.LeaseID, RepositoryID: server.repositoryID,
		MutationKind: "put", ObjectType: object.objectType, ObjectName: object.name, Digest: "sha256:" + hex.EncodeToString(hasher.Sum(nil)),
		Bytes: bytes, RecoveryEpoch: server.retentionLease.RecoveryEpoch}
	if err := server.retentionJournal.BeginRetainedMutation(r.Context(), attempt); err != nil {
		http.Error(w, "journal unavailable", http.StatusServiceUnavailable)
		return
	}
	server.retentionMutations++
	server.retentionBytes += bytes
	destFD, err := server.openTypeDir(object.objectType, false)
	if err != nil {
		http.Error(w, "uncertain", http.StatusServiceUnavailable)
		return
	}
	defer unix.Close(destFD)
	if err := unix.Renameat2(stagingFD, object.name, destFD, object.name, unix.RENAME_NOREPLACE); err != nil {
		http.Error(w, "uncertain", http.StatusServiceUnavailable)
		return
	}
	if unix.Fsync(stagingFD) != nil || unix.Fsync(destFD) != nil {
		http.Error(w, "uncertain", http.StatusServiceUnavailable)
		return
	}
	if err := server.retentionJournal.FinishRetainedMutation(r.Context(), RetainedMutationOutcome{LeaseID: server.retentionLease.LeaseID,
		ObjectType: object.objectType, ObjectName: object.name, Status: "created"}); err != nil {
		http.Error(w, "uncertain", http.StatusServiceUnavailable)
		return
	}
	if object.isLock {
		server.ownLocks[object.name] = struct{}{}
	}
	w.WriteHeader(http.StatusOK)
}

func (server *RESTServer) handleRetainedDelete(w http.ResponseWriter, r *http.Request, object objectRequest) {
	// Config and keys are never retirement targets. Snapshot IDs are always
	// prelisted; pack and index IDs are dynamically journaled by restic prune.
	if object.isConfig || object.objectType == "keys" || (object.objectType == "snapshots" && !server.plannedSnapshot(object.name)) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	fileFD, err := server.openObject(object, false)
	if err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	file := os.NewFile(uintptr(fileFD), object.name)
	if file == nil {
		unix.Close(fileFD)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	hasher := sha256.New()
	bytes, hashErr := io.Copy(hasher, file)
	closeErr := file.Close()
	if hashErr != nil || closeErr != nil || bytes < 0 {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	if object.isLock {
		if _, own := server.ownLocks[object.name]; !own {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
	}
	if server.retentionMutations >= server.retentionLease.MaxMutations || bytes > server.retentionLease.MaxMutationBytes-server.retentionBytes {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	attempt := RetainedMutationAttempt{LeaseID: server.retentionLease.LeaseID, RepositoryID: server.repositoryID,
		MutationKind: "delete", ObjectType: object.objectType, ObjectName: object.name, Digest: "sha256:" + hex.EncodeToString(hasher.Sum(nil)), Bytes: bytes,
		RecoveryEpoch: server.retentionLease.RecoveryEpoch}
	if err := server.retentionJournal.BeginRetainedMutation(r.Context(), attempt); err != nil {
		http.Error(w, "journal unavailable", http.StatusServiceUnavailable)
		return
	}
	server.retentionMutations++
	server.retentionBytes += bytes
	sourceFD, err := server.openTypeDir(object.objectType, false)
	if err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	defer unix.Close(sourceFD)
	holdFD, err := server.openQuarantineTypeDir(object.objectType)
	if err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	defer unix.Close(holdFD)
	if err := unix.Renameat2(sourceFD, object.name, holdFD, object.name, unix.RENAME_NOREPLACE); err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if unix.Fsync(sourceFD) != nil || unix.Fsync(holdFD) != nil {
		http.Error(w, "uncertain", http.StatusServiceUnavailable)
		return
	}
	outcome := RetainedMutationOutcome{LeaseID: server.retentionLease.LeaseID, ObjectType: object.objectType,
		ObjectName: object.name, QuarantineName: object.objectType + "/" + object.name, Status: "quarantined"}
	if err := server.retentionJournal.FinishRetainedMutation(r.Context(), outcome); err != nil {
		http.Error(w, "uncertain", http.StatusServiceUnavailable)
		return
	}
	if object.isLock {
		delete(server.ownLocks, object.name)
	}
	w.WriteHeader(http.StatusOK)
}

func (server *RESTServer) plannedSnapshot(name string) bool {
	for _, allowed := range server.retentionLease.PlannedSnapshotIDs {
		if allowed == name {
			return true
		}
	}
	return false
}
