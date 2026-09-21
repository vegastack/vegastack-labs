package backup

import (
	"strings"
	"time"
)

// WriterLease binds exactly one writer to one repository for one exact
// plan/run/step at a recovery epoch. It carries no secret material. The REST
// boundary verifies it before every mutation.
type WriterLease struct {
	PolicyID         string
	PointID          string
	PlanID           string
	PlanDigest       string
	RunID            string
	StepID           string
	LeaseID          string
	RepositoryID     string
	RepositoryClass  string
	TargetID         string
	SourceRevision   int64
	RecoveryEpoch    int64
	MaximumExpiresAt time.Time
}

// LeaseVerifier confirms a writer lease is still the single active lease for its
// repository at the current epoch and has not expired. The store-owned backup
// lease repository implements it; the REST boundary calls it before every write.
type LeaseVerifier interface {
	VerifyWriterLease(lease WriterLease, now time.Time) error
}

// retainedObjectTypes are the restic repository-format-v2 object classes that are
// immutable once created. The routine writer may never overwrite or delete them.
var retainedObjectTypes = map[string]struct{}{
	"config":    {},
	"keys":      {},
	"data":      {},
	"index":     {},
	"snapshots": {},
}

// objectRequest is the parsed, validated form of one restic REST request path.
type objectRequest struct {
	repositoryID     string
	objectType       string // "config" | "keys" | "data" | "index" | "snapshots" | "locks"
	name             string // "" for the config object; 64-hex otherwise
	isConfig         bool
	isLock           bool
	retained         bool
	isRepositoryRoot bool // POST /<repo>/ (with ?create=true): create the layout
	isList           bool // GET /<repo>/<type>/: list objects of that type
}

// listableObjectTypes are the restic repository-format-v2 object classes a
// directory listing may enumerate.
var listableObjectTypes = map[string]struct{}{
	"keys": {}, "data": {}, "index": {}, "snapshots": {}, "locks": {},
}

// parseRepositoryRequest classifies a restic REST request path that is not a
// single object: the repository root (for create) or a type directory (for
// listing). It returns false for anything else so the object parser can run.
func parseRepositoryRequest(path, expectedRepositoryID string) (objectRequest, bool) {
	if expectedRepositoryID == "" || !validObjectSegment(expectedRepositoryID) {
		return objectRequest{}, false
	}
	trimmed := strings.TrimPrefix(path, "/")
	// Repository root: "<repo>" or "<repo>/".
	if trimmed == expectedRepositoryID || trimmed == expectedRepositoryID+"/" {
		return objectRequest{repositoryID: expectedRepositoryID, isRepositoryRoot: true}, true
	}
	// Type directory listing: "<repo>/<type>/".
	if !strings.HasSuffix(trimmed, "/") {
		return objectRequest{}, false
	}
	segments := strings.Split(strings.TrimSuffix(trimmed, "/"), "/")
	if len(segments) != 2 || segments[0] != expectedRepositoryID || !validObjectSegment(segments[1]) {
		return objectRequest{}, false
	}
	if _, ok := listableObjectTypes[segments[1]]; !ok {
		return objectRequest{}, false
	}
	return objectRequest{repositoryID: segments[0], objectType: segments[1], isList: true}, true
}

// parseObjectPath validates one restic REST object path of the form
// /<repository-id>/<type>[/<name>] against the exact expected repository ID. It
// rejects traversal, empty or non-canonical segments, unknown types and
// malformed object names before any filesystem access.
func parseObjectPath(path, expectedRepositoryID string) (objectRequest, bool) {
	if expectedRepositoryID == "" || !validObjectSegment(expectedRepositoryID) {
		return objectRequest{}, false
	}
	trimmed := strings.TrimPrefix(path, "/")
	segments := strings.Split(trimmed, "/")
	if len(segments) < 2 || len(segments) > 3 {
		return objectRequest{}, false
	}
	for _, segment := range segments {
		if !validObjectSegment(segment) {
			return objectRequest{}, false
		}
	}
	if segments[0] != expectedRepositoryID {
		return objectRequest{}, false
	}
	objectType := segments[1]
	request := objectRequest{repositoryID: segments[0], objectType: objectType}
	if objectType == "config" {
		if len(segments) != 2 {
			return objectRequest{}, false
		}
		request.isConfig = true
		request.retained = true
		request.name = "config"
		return request, true
	}
	switch objectType {
	case "keys", "data", "index", "snapshots":
		request.retained = true
	case "locks":
		request.isLock = true
	default:
		return objectRequest{}, false
	}
	if len(segments) != 3 || !validObjectName(segments[2]) {
		return objectRequest{}, false
	}
	request.name = segments[2]
	return request, true
}

// validObjectSegment rejects empty, dot, traversal, separator-bearing and
// NUL-bearing path segments. It is the first-line traversal guard.
func validObjectSegment(segment string) bool {
	if segment == "" || segment == "." || segment == ".." || len(segment) > 128 {
		return false
	}
	for _, character := range segment {
		if character == 0 || character == '/' || character == '\\' {
			return false
		}
	}
	return true
}

// validObjectName requires a 64-character lowercase hex restic object identifier.
func validObjectName(name string) bool {
	if len(name) != 64 {
		return false
	}
	for _, character := range name {
		if !strings.ContainsRune("0123456789abcdef", character) {
			return false
		}
	}
	return true
}
