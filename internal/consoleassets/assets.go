// Package consoleassets owns the generated static Console embedded in vsk-labs.
package consoleassets

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"path"
	"strings"
)

//go:embed all:dist manifest.json
var embedded embed.FS

type Asset struct {
	SHA256      string `json:"sha256"`
	Size        int64  `json:"size"`
	ContentType string `json:"contentType"`
	Immutable   bool   `json:"immutable"`
}

type Manifest struct {
	SchemaVersion         int              `json:"schemaVersion"`
	BuildDigest           string           `json:"buildDigest"`
	ContentSecurityPolicy string           `json:"contentSecurityPolicy"`
	Files                 map[string]Asset `json:"files"`
}

func Open() (fs.FS, Manifest, error) {
	content, err := embedded.ReadFile("manifest.json")
	if err != nil {
		return nil, Manifest{}, errors.New("embedded Console manifest unavailable")
	}
	decoder := json.NewDecoder(strings.NewReader(string(content)))
	decoder.DisallowUnknownFields()
	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil || manifest.SchemaVersion != 1 || len(manifest.Files) == 0 || len(manifest.BuildDigest) != 64 || manifest.ContentSecurityPolicy == "" {
		return nil, Manifest{}, errors.New("embedded Console manifest invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err == nil {
		return nil, Manifest{}, errors.New("embedded Console manifest invalid")
	}
	files, err := fs.Sub(embedded, "dist")
	if err != nil {
		return nil, Manifest{}, errors.New("embedded Console unavailable")
	}
	seen := make(map[string]bool, len(manifest.Files))
	err = fs.WalkDir(files, ".", func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() || name == "." || path.Clean(name) != name || strings.Contains(name, "\\") {
			return errors.New("embedded Console contains invalid path")
		}
		asset, ok := manifest.Files[name]
		if !ok || seen[name] || asset.Size < 0 || asset.ContentType == "" || len(asset.SHA256) != 64 {
			return errors.New("embedded Console manifest mismatch")
		}
		bytes, readErr := fs.ReadFile(files, name)
		if readErr != nil {
			return readErr
		}
		digest := sha256.Sum256(bytes)
		if int64(len(bytes)) != asset.Size || hex.EncodeToString(digest[:]) != asset.SHA256 {
			return errors.New("embedded Console manifest mismatch")
		}
		seen[name] = true
		return nil
	})
	if err != nil || len(seen) != len(manifest.Files) {
		return nil, Manifest{}, errors.New("embedded Console manifest mismatch")
	}
	if index, ok := manifest.Files["index.html"]; !ok || index.Size == 0 || index.ContentType != "text/html; charset=utf-8" {
		return nil, Manifest{}, errors.New("embedded Console index unavailable")
	}
	digestInput, err := json.Marshal(struct {
		Files                 map[string]Asset `json:"files"`
		ContentSecurityPolicy string           `json:"contentSecurityPolicy"`
	}{Files: manifest.Files, ContentSecurityPolicy: manifest.ContentSecurityPolicy})
	if err != nil {
		return nil, Manifest{}, errors.New("embedded Console manifest invalid")
	}
	digest := sha256.Sum256(digestInput)
	if hex.EncodeToString(digest[:]) != manifest.BuildDigest {
		return nil, Manifest{}, errors.New("embedded Console manifest digest mismatch")
	}
	return files, manifest, nil
}
