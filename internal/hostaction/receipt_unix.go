//go:build linux || darwin

package hostaction

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sync"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"golang.org/x/sys/unix"
)

var digestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

type Receipts struct {
	mu     sync.Mutex
	dir    *os.File
	uid    uint32
	claims map[string]bool
}

func OpenReceipts(path string, uid uint32) (*Receipts, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, blocked()
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, blocked()
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Uid != uid || st.Mode&077 != 0 {
		unix.Close(fd)
		return nil, blocked()
	}
	return &Receipts{dir: os.NewFile(uintptr(fd), "host-action-receipts"), uid: uid, claims: map[string]bool{}}, nil
}
func (r *Receipts) Claim(digest string) error { return r.ClaimExecution(digest, digest) }
func (r *Receipts) ClaimExecution(key, digest string) error {
	if r == nil {
		return blocked()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.dir == nil || !digestPattern.MatchString(key) || !digestPattern.MatchString(digest) {
		return blocked()
	}
	fd, err := unix.Openat(int(r.dir.Fd()), key[7:]+".json", unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return blocked()
	}
	file := os.NewFile(uintptr(fd), "claimed-host-action")
	// Even a partial write is preserved: uncertain dispatch must never replay.
	raw, _ := json.Marshal(struct {
		BundleDigest string `json:"bundleDigest"`
		Status       string `json:"status"`
	}{digest, "claimed"})
	_, writeErr := file.Write(raw)
	syncErr := file.Sync()
	closeErr := file.Close()
	dirErr := r.dir.Sync()
	if writeErr != nil || syncErr != nil || closeErr != nil || dirErr != nil {
		return blocked()
	}
	r.claims[key+"/"+digest] = true
	return nil
}
func (r *Receipts) Finish(digest string, result generated.HostActionResult) error {
	return r.FinishExecution(digest, digest, result)
}
func (r *Receipts) FinishExecution(key, digest string, result generated.HostActionResult) error {
	if r == nil {
		return blocked()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	raw, err := json.Marshal(result)
	if r.dir == nil || !digestPattern.MatchString(digest) || !digestPattern.MatchString(key) || !r.claims[key+"/"+digest] || result.BundleDigest != digest || err != nil || len(raw) > MaximumResultFrame || ValidateResult(result) != nil {
		return blocked()
	}
	// Never replace the durable claim. A separate exclusive result retains the
	// original consumed marker even if recording the effect crashes.
	fd, err := unix.Openat(int(r.dir.Fd()), key[7:]+".result.json", unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return blocked()
	}
	file := os.NewFile(uintptr(fd), "host-action-result")
	_, we := file.Write(raw)
	se := file.Sync()
	ce := file.Close()
	de := r.dir.Sync()
	if we != nil || se != nil || ce != nil || de != nil {
		return blocked()
	}
	delete(r.claims, key+"/"+digest)
	return nil
}
func (r *Receipts) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.dir == nil {
		return nil
	}
	err := r.dir.Close()
	r.dir = nil
	return err
}
