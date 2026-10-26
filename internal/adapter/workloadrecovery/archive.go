package workloadrecovery

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path"
	"sort"
	"strings"
)

type contentEntry struct {
	Name, Kind, Digest, Link string
	Mode, UID, GID           int64
	Size                     int64
}

// archiveProof inspects actual archive content without extracting untrusted
// entries into the controller filesystem. Ownership and file modes are included;
// unstable tar headers and timestamps do not affect the content proof.
func archiveProof(file string, max int64, empty bool) (string, int64, error) {
	f, e := os.Open(file)
	if e != nil {
		return "", 0, unavailable()
	}
	defer f.Close()
	stat, e := f.Stat()
	if e != nil || stat.Size() > max || stat.Size() < 1024 {
		return "", 0, invalid()
	}
	r := tar.NewReader(io.LimitReader(f, max+1))
	seen := map[string]bool{}
	var entries []contentEntry
	var total int64
	for {
		h, e := r.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return "", 0, invalid()
		}
		n := path.Clean(h.Name)
		if path.IsAbs(n) || n == ".." || strings.HasPrefix(n, "../") || strings.ContainsRune(n, 0) || seen[n] {
			return "", 0, invalid()
		}
		seen[n] = true
		if len(entries) > 1000000 || h.Size < 0 || h.Size > max-total {
			return "", 0, invalid()
		}
		total += h.Size
		v := contentEntry{Name: n, Mode: h.Mode, UID: int64(h.Uid), GID: int64(h.Gid), Size: h.Size}
		switch h.Typeflag {
		case tar.TypeDir:
			v.Kind = "directory"
		case tar.TypeReg, tar.TypeRegA:
			v.Kind = "file"
			hash := sha256.New()
			if copied, e := io.Copy(hash, r); e != nil || copied != h.Size {
				return "", 0, invalid()
			}
			v.Digest = "sha256:" + hex.EncodeToString(hash.Sum(nil))
		case tar.TypeSymlink, tar.TypeLink:
			v.Kind = "link"
			v.Link = h.Linkname
			resolved := path.Clean(path.Join(path.Dir(n), h.Linkname))
			if path.IsAbs(h.Linkname) || resolved == ".." || strings.HasPrefix(resolved, "../") {
				return "", 0, invalid()
			}
		default:
			return "", 0, invalid()
		}
		// Docker's root directory header is the destination directory itself. Its
		// ownership can differ before copy; child entries must be exactly preserved.
		if n != "." || !empty {
			if empty && n != "." {
				return "", 0, blocked()
			}
			entries = append(entries, v)
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	raw, e := json.Marshal(entries)
	if e != nil {
		return "", 0, invalid()
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), stat.Size(), nil
}
