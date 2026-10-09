package hostaction

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	protocol "github.com/vegastack/vegastack-labs/internal/hostaction"
)

// InstalledAnsibleCollectionDigest seals the pinned Debian ansible-core package
// source/assets. Bytecode caches are derived and excluded; symlinked or writable
// package entries fail closed. This is a read-only qualification primitive.
func InstalledAnsibleCollectionDigest() (string, error) {
	return ansibleTreeDigest("/usr/lib/python3/dist-packages/ansible")
}
func ansibleTreeDigest(root string) (string, error) {
	if !protectedRendererPath(root) {
		return "", denied()
	}
	type entry struct{ Path, Digest string }
	var entries []entry
	var total int64
	err := filepath.WalkDir(root, func(path string, item fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := item.Info()
		if err != nil || item.Type()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 || !rendererRootOwner(info) {
			return denied()
		}
		if item.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() || info.Size() > 8<<20 || len(entries) >= 8192 {
			return denied()
		}
		total += info.Size()
		if total > 64<<20 {
			return denied()
		}
		rel, err := filepath.Rel(root, path)
		if err != nil || strings.HasPrefix(rel, "..") {
			return denied()
		}
		if strings.HasPrefix(filepath.ToSlash(rel), "__pycache__/") || strings.Contains(filepath.ToSlash(rel), "/__pycache__/") {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		entries = append(entries, entry{filepath.ToSlash(rel), protocol.BytesDigest(raw)})
		return nil
	})
	if err != nil || len(entries) == 0 {
		return "", denied()
	}
	return protocol.Digest(entries), nil
}
