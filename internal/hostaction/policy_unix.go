//go:build linux || darwin

package hostaction

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"

	"context"
	"crypto/ed25519"
	"github.com/vegastack/vegastack-labs/internal/strictjson"
	"golang.org/x/sys/unix"
)

// LoadPolicy only accepts a policy reached through root-owned protected path
// components. The automation account cannot choose the trust anchor.
func LoadPolicy(path string) (Policy, error) {
	p, err := loadPolicy(path, 0)
	if err != nil || !protectedReceiptDirectory(p.ReceiptDirectory) {
		return Policy{}, blocked()
	}
	return p, nil
}
func loadPolicy(path string, owner uint32) (Policy, error) {
	var p Policy
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return p, blocked()
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return p, blocked()
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i, part := range parts {
		flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC
		if i < len(parts)-1 {
			flags |= unix.O_DIRECTORY
		}
		next, e := unix.Openat(fd, part, flags, 0)
		unix.Close(fd)
		if e != nil {
			return p, blocked()
		}
		fd = next
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || (st.Uid != 0 && st.Uid != owner) || st.Mode&022 != 0 || (i == len(parts)-1 && (st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Size < 1 || st.Size > MaximumFrame)) {
			unix.Close(fd)
			return p, blocked()
		}
	}
	file := os.NewFile(uintptr(fd), "host-action-policy")
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, MaximumFrame+1))
	if err != nil || len(raw) > MaximumFrame || strictjson.Scan(context.Background(), raw, strictjson.Limits{MaxDepth: 4}) != nil {
		return p, blocked()
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&p) != nil || p.CallerUID == 0 || p.KeyID == "" || p.HostID == "" || !digestPattern.MatchString(p.HostIdentityDigest) || len(p.PublicKey) != ed25519.PublicKeySize || !filepath.IsAbs(p.ReceiptDirectory) || filepath.Clean(p.ReceiptDirectory) != p.ReceiptDirectory {
		return Policy{}, blocked()
	}
	return p, nil
}

func protectedReceiptDirectory(path string) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return false
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return false
	}
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if e != nil {
			return false
		}
		fd = next
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || st.Uid != 0 || st.Mode&022 != 0 {
			unix.Close(fd)
			return false
		}
	}
	unix.Close(fd)
	return true
}
