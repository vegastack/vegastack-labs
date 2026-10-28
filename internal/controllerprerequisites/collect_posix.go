//go:build linux || darwin

package controllerprerequisites

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func digest(b []byte) string { h := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(h[:]) }

// Root is unexported and supplied only by local filesystem fixtures. Production
// always uses the fixed OS root; there is no caller-selected path or command.
func collectRoot(ctx context.Context, expected, root string) generated.ControllerPrerequisitesData {
	out := empty("linux")
	raw, _, e := readFixed(ctx, root, "/etc/machine-id", 128)
	if e != nil || !machineID.MatchString(expected) || strings.TrimSpace(string(raw)) != expected {
		return out
	}
	out.IdentityMatched = true
	add := func(f generated.ControllerPrerequisiteFact) { out.Facts = append(out.Facts, f) }
	passwd, _, err := readFixed(ctx, root, "/etc/passwd", 1<<20)
	account := fact("account", "unavailable")
	if err == nil {
		account.State = "missing"
		for _, line := range strings.Split(string(passwd), "\n") {
			p := strings.Split(line, ":")
			if len(p) == 7 && p[0] == "vsk-labs" {
				uid, e1 := strconv.ParseUint(p[2], 10, 32)
				gid, e2 := strconv.ParseUint(p[3], 10, 32)
				if e1 == nil && e2 == nil {
					account.State = "present"
					account.UID = strconv.FormatUint(uid, 10)
					account.GID = strconv.FormatUint(gid, 10)
				} else {
					account.State = "invalid"
				}
				break
			}
		}
	}
	add(account)
	for _, entry := range []struct {
		selector, path string
		hash           bool
	}{
		{"profile", "/etc/vsk-labs/control/server.json", true}, {"executable", "/usr/local/bin/vsk-labs", true}, {"state", "/var/lib/vsk-labs/control", false}, {"runtime", "/run/vsk-labs-control", false}, {"unit", "/etc/systemd/system/vsk-labs.service", true}, {"custody-policy", "/etc/vsk-labs/native-credential-authority.json", false}, {"credential-drafts", "/var/lib/vsk-labs/control/credential-drafts", false},
	} {
		f := fact(entry.selector, "unavailable")
		info, err := inspect(root, entry.path)
		if err != nil {
			f.State = state(err)
			add(f)
			continue
		}
		f.State = "present"
		f.Mode = info.Mode().Perm().String()
		if st, ok := info.Sys().(*syscall.Stat_t); ok {
			f.UID = strconv.FormatUint(uint64(st.Uid), 10)
			f.GID = strconv.FormatUint(uint64(st.Gid), 10)
		}
		if entry.hash {
			b, _, err := readFixed(ctx, root, entry.path, 64<<20)
			if err != nil {
				f.State = state(err)
			} else {
				f.Digest = digest(b)
			}
		}
		add(f)
	}
	// Only the public certificate selected by the canonical protected profile is
	// read. Never open tlsPrivateKeyPath, credentials or credential draft contents.
	tls := fact("tls-certificate", "unavailable")
	profile, info, err := readFixed(ctx, root, "/etc/vsk-labs/control/server.json", 1<<20)
	if err == nil && info.Mode().Perm()&0077 == 0 {
		var config struct {
			RemoteRead struct {
				Enabled     bool   `json:"enabled"`
				Certificate string `json:"tlsCertificatePath"`
			} `json:"remoteRead"`
		}
		if json.Unmarshal(profile, &config) != nil {
			tls.State = "invalid"
		} else if !config.RemoteRead.Enabled {
			tls.State = "disabled"
		} else {
			path := config.RemoteRead.Certificate
			if path != "/etc/vsk-labs/control/tls/server.crt" {
				tls.State = "unsafe"
			} else if b, _, err := readFixed(ctx, root, path, 1<<20); err != nil {
				tls.State = state(err)
			} else {
				block, _ := pem.Decode(b)
				if block == nil || block.Type != "CERTIFICATE" {
					tls.State = "invalid"
				} else if cert, err := x509.ParseCertificate(block.Bytes); err != nil {
					tls.State = "invalid"
				} else {
					tls.State = "present"
					tls.Digest = digest(cert.Raw)
					tls.NotAfter = cert.NotAfter.UTC().Format(time.RFC3339)
					names := strings.Join(cert.DNSNames, ",")
					if len(names) <= 2048 {
						tls.DNSNames = names
					}
				}
			}
		}
	}
	add(tls)
	return out
}
func fact(selector, state string) generated.ControllerPrerequisiteFact {
	return generated.ControllerPrerequisiteFact{Schema: generated.SchemaIDControllerPrerequisiteFact, SchemaVersion: "1.0.0", Selector: selector, State: state}
}

var unsafePath = errors.New("unsafe fixed metadata path")

func state(e error) string {
	if errors.Is(e, os.ErrNotExist) {
		return "missing"
	}
	if errors.Is(e, unsafePath) {
		return "unsafe"
	}
	return "unavailable"
}
func inspect(root, path string) (os.FileInfo, error) {
	current := root
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		current = filepath.Join(current, part)
		s, e := os.Lstat(current)
		if e != nil {
			return nil, e
		}
		if s.Mode()&os.ModeSymlink != 0 {
			return nil, unsafePath
		}
	}
	s, e := os.Lstat(current)
	if e != nil {
		return nil, e
	}
	if !s.IsDir() && !s.Mode().IsRegular() {
		return nil, unsafePath
	}
	return s, nil
}
func readFixed(ctx context.Context, root, path string, limit int64) ([]byte, os.FileInfo, error) {
	if e := ctx.Err(); e != nil {
		return nil, nil, e
	}
	before, e := inspect(root, path)
	if e != nil {
		return nil, nil, e
	}
	if !before.Mode().IsRegular() || before.Size() > limit {
		return nil, nil, unsafePath
	}
	fd, e := openFixed(root, path)
	if e != nil {
		return nil, nil, e
	}
	f := os.NewFile(uintptr(fd), "controller-public-metadata")
	defer f.Close()
	opened, e := f.Stat()
	if e != nil || !os.SameFile(before, opened) {
		return nil, nil, unsafePath
	}
	b, e := io.ReadAll(io.LimitReader(f, limit+1))
	if e != nil {
		return nil, nil, e
	}
	after, e := f.Stat()
	if e != nil || !os.SameFile(before, after) || before.Size() != after.Size() || before.ModTime() != after.ModTime() || len(b) > int(limit) {
		return nil, nil, unsafePath
	}
	return b, after, nil
}

// Walk every directory by descriptor without following links, including under
// concurrent path replacement. Final descriptor identity is checked above.
func openFixed(root, path string) (int, error) {
	parent, e := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return -1, e
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i, part := range parts {
		flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
		if i < len(parts)-1 {
			flags |= unix.O_DIRECTORY
		}
		next, err := unix.Openat(parent, part, flags, 0)
		unix.Close(parent)
		if err != nil {
			return -1, err
		}
		parent = next
	}
	return parent, nil
}
