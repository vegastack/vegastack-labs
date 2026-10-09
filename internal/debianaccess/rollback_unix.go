//go:build linux || darwin

package debianaccess

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path"
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/strictjson"
	"golang.org/x/sys/unix"
)

// All production callers use filesystemRoot="/". Other roots are internal test injection.
func withRollback(ctx context.Context, filesystemRoot string, fn func(*os.Root) error) error {
	if ctx == nil || ctx.Err() != nil {
		return errAccess
	}
	root, err := os.OpenRoot(filesystemRoot)
	if err != nil {
		return err
	}
	defer root.Close()
	for i := range strings.Split(rollbackDirectory, "/") {
		part := strings.Join(strings.Split(rollbackDirectory, "/")[:i+1], "/")
		if _, e := root.Lstat(part); os.IsNotExist(e) {
			if e = root.Mkdir(part, 0700); e != nil {
				return e
			}
		} else if e != nil {
			return e
		}
		if e := checkProtected(root, part, true); e != nil {
			return e
		}
	}
	if err = checkProtected(root, rollbackDirectory, true); err != nil {
		return err
	}
	lock, err := root.OpenFile(rollbackDirectory+"/lock", os.O_RDWR|os.O_CREATE|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	var st unix.Stat_t
	if unix.Fstat(int(lock.Fd()), &st) != nil || st.Nlink != 1 || st.Uid != uint32(os.Geteuid()) || st.Mode&0077 != 0 {
		return errAccess
	}
	if err = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return err
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	return fn(root)
}
func checkProtected(root *os.Root, p string, directory bool) error {
	parts := strings.Split(p, "/")
	for i := range parts {
		component := strings.Join(parts[:i+1], "/")
		info, err := root.Lstat(component)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
			return errAccess
		}
		f, e := root.OpenFile(component, os.O_RDONLY|unix.O_NOFOLLOW, 0)
		if e != nil {
			return e
		}
		var st unix.Stat_t
		e = unix.Fstat(int(f.Fd()), &st)
		f.Close()
		if e != nil || st.Uid != uint32(os.Geteuid()) {
			return errAccess
		}
		if i < len(parts)-1 || directory {
			if !info.IsDir() {
				return errAccess
			}
		} else if !info.Mode().IsRegular() || st.Nlink != 1 {
			return errAccess
		}
	}
	return nil
}
func readProtected(root *os.Root, p string) ([]byte, os.FileMode, error) {
	if err := checkProtected(root, p, false); err != nil {
		return nil, 0, err
	}
	f, err := root.OpenFile(p, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || info.Size() > 1048576 {
		return nil, 0, errAccess
	}
	b, err := io.ReadAll(io.LimitReader(f, 1048577))
	return b, info.Mode().Perm(), err
}
func writeAtomic(root *os.Root, p string, b []byte, mode os.FileMode) error {
	parent := path.Dir(p)
	if err := checkProtected(root, parent, true); err != nil {
		return err
	}
	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		return err
	}
	tmp := parent + "/.vsk-" + hex.EncodeToString(token[:])
	f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, mode)
	if err != nil {
		return err
	}
	defer root.Remove(tmp)
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = root.Rename(tmp, p); err != nil {
		return err
	}
	d, err := root.Open(parent)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
func readRollback(root *os.Root) (RollbackRecord, error) {
	var r RollbackRecord
	b, _, err := readProtected(root, rollbackRecordPath)
	if err != nil {
		return r, err
	}
	if strictjson.Scan(context.Background(), b, strictjson.Limits{MaxDepth: 16}) != nil {
		return r, errAccess
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if dec.Decode(&r) != nil || !validRollback(r) {
		return r, errAccess
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return r, errAccess
	}
	return r, nil
}
func saveRollback(root *os.Root, r RollbackRecord) error {
	if !validRollback(r) {
		return errAccess
	}
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if len(b) > 1048576 {
		return errAccess
	}
	return writeAtomic(root, rollbackRecordPath, b, 0600)
}
func Arm(ctx context.Context, root string, r RollbackRecord) error {
	if !validRollback(r) || r.State != "armed" {
		return errAccess
	}
	return withRollback(ctx, root, func(fs *os.Root) error {
		old, err := readRollback(fs)
		if err == nil && (old.State == "armed" || old.State == "uncertain") {
			return errAccess
		}
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		for _, f := range r.Files {
			b, mode, e := readProtected(fs, f.Path)
			if !f.BeforePresent {
				if !os.IsNotExist(e) {
					return errAccess
				}
				if e = checkProtected(fs, path.Dir(f.Path), true); e != nil {
					return e
				}
			} else if e != nil || !bytes.Equal(b, f.Before) || mode != f.BeforeMode {
				return errAccess
			}
		}
		return saveRollback(fs, r)
	})
}

// Restore performs file restoration only; native runtime supplies the compiled firewall
// and sshd reload hooks through restoreWith. The record stays armed on hook failure.
func Restore(ctx context.Context, root, digest string) error {
	return restoreWith(ctx, root, digest, nil)
}
func restoreWith(ctx context.Context, root, digest string, finish func(RollbackRecord) error) error {
	return withRollback(ctx, root, func(fs *os.Root) error {
		r, err := readRollback(fs)
		if err != nil || r.Digest() != digest {
			return errAccess
		}
		if r.State == "restored" {
			return nil
		}
		if r.State != "armed" {
			return errAccess
		}
		uncertain := func() error { r.State = "uncertain"; _ = saveRollback(fs, r); return errAccess }
		for _, f := range r.Files {
			b, mode, e := readProtected(fs, f.Path)
			if e != nil {
				if !f.BeforePresent && os.IsNotExist(e) {
					continue
				}
				return uncertain()
			}
			if (digestBytes(b) != f.AfterDigest || mode != f.AfterMode) && (!f.BeforePresent || !bytes.Equal(b, f.Before) || mode != f.BeforeMode) {
				return uncertain()
			}
		}
		for _, f := range r.Files {
			if f.BeforePresent {
				if err = writeAtomic(fs, f.Path, f.Before, f.BeforeMode); err != nil {
					return uncertain()
				}
			} else {
				err = fs.Remove(f.Path)
				if err != nil && !os.IsNotExist(err) {
					return uncertain()
				}
				d, e := fs.Open(path.Dir(f.Path))
				if e != nil {
					return uncertain()
				}
				e = d.Sync()
				d.Close()
				if e != nil {
					return uncertain()
				}
			}
		}
		if len(r.Firewall) > 0 && finish == nil {
			return uncertain()
		}
		if finish != nil {
			if err = finish(r); err != nil {
				return uncertain()
			}
		}
		r.State = "restored"
		return saveRollback(fs, r)
	})
}
func Confirm(ctx context.Context, root, digest, probeDigest string) error {
	return confirmAt(ctx, root, digest, probeDigest, time.Now().UTC())
}
func confirmAt(ctx context.Context, root, digest, probeDigest string, now time.Time) error {
	if !digestRE.MatchString(probeDigest) {
		return errAccess
	}
	return withRollback(ctx, root, func(fs *os.Root) error {
		r, err := readRollback(fs)
		if err != nil || r.Digest() != digest || r.State != "armed" || now.Before(r.ArmedAt) || !now.Before(r.Deadline) {
			return errAccess
		}
		for _, f := range r.Files {
			b, mode, e := readProtected(fs, f.Path)
			if e != nil || digestBytes(b) != f.AfterDigest || mode != f.AfterMode {
				return errAccess
			}
		}
		r.State = "confirmed"
		r.ProbeDigest = probeDigest
		return saveRollback(fs, r)
	})
}
