package store

import (
	"crypto/sha256"
	"embed"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strings"
)

// Migration ownership is fixed: 0001 belongs to #30, 0002 to #31, 0003 to
// #33, 0004 to #35, 0005 to #54, and 0006 to #76.

//go:embed migrations/*.sql
var embeddedMigrations embed.FS

type Migration struct {
	ID     uint64
	Name   string
	SHA256 [32]byte
	SQL    string
}

type migrationManifestEntry struct {
	ID     uint64
	Name   string
	SHA256 [32]byte
}

var migrationNamePattern = regexp.MustCompile(`^[0-9]{4}_[a-z][a-z0-9_]*$`)

var embeddedMigrationManifest = []migrationManifestEntry{
	{ID: 1, Name: "0001_store_foundation", SHA256: mustSHA256("05c15b90ff0805b8b74b90d5cf61691ddcb44a9e80e92ba78c7610c393f40191")},
	{ID: 2, Name: "0002_inventory_drafts", SHA256: mustSHA256("6e6be190299476299314831f0519f4c0abc7d161a871152d95fda5089edcda6e")},
	{ID: 3, Name: "0003_audit_outbox", SHA256: mustSHA256("e783eea0ed8780c490127a4328fc9da398ce902dc73d47a83c3c82380bf453aa")},
	{ID: 4, Name: "0004_read_authorization", SHA256: mustSHA256("d6a7820902d336726fd2fb6aa7295d9aa29695f0a010628c3edca1f56f40fc3c")},
	{ID: 5, Name: "0005_browser_sessions", SHA256: mustSHA256("33561ec8fb60b4c9a3bfee670579dbdb85df35cd23a3cd520488f815f560e145")},
	{ID: 6, Name: "0006_declarations_and_plans", SHA256: mustSHA256("afe871edab8c40a4b2c2de203bb8d7a6d7cb926d707edf804ab3c3e955403044")},
}

func Catalog() ([]Migration, error) {
	return catalogFromFS(embeddedMigrations, embeddedMigrationManifest)
}

func catalogFromFS(source fs.FS, manifest []migrationManifestEntry) ([]Migration, error) {
	if source == nil || len(manifest) == 0 {
		return nil, migrationCatalogError(errors.New("catalog is empty"))
	}
	entries, err := fs.ReadDir(source, "migrations")
	if err != nil {
		return nil, migrationCatalogError(err)
	}
	files := make(map[string]bool, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || path.Ext(entry.Name()) != ".sql" {
			return nil, migrationCatalogError(errors.New("catalog contains an unexpected entry"))
		}
		files[strings.TrimSuffix(entry.Name(), ".sql")] = true
	}
	if len(files) != len(manifest) {
		return nil, migrationCatalogError(errors.New("catalog and manifest differ"))
	}

	seenNames := make(map[string]bool, len(manifest))
	catalog := make([]Migration, 0, len(manifest))
	for index, entry := range manifest {
		expectedID := uint64(index + 1)
		if entry.ID != expectedID || seenNames[entry.Name] || !migrationNamePattern.MatchString(entry.Name) || entry.Name[:4] != fmt.Sprintf("%04d", entry.ID) {
			return nil, migrationCatalogError(errors.New("migration sequence is invalid"))
		}
		seenNames[entry.Name] = true
		if !files[entry.Name] {
			return nil, migrationCatalogError(errors.New("migration file is missing"))
		}
		body, err := fs.ReadFile(source, "migrations/"+entry.Name+".sql")
		if err != nil {
			return nil, migrationCatalogError(err)
		}
		if strings.TrimSpace(string(body)) == "" {
			return nil, migrationCatalogError(errors.New("migration body is empty"))
		}
		actual := sha256.Sum256(body)
		if actual != entry.SHA256 {
			return nil, migrationCatalogError(errors.New("migration checksum differs"))
		}
		catalog = append(catalog, Migration{ID: entry.ID, Name: entry.Name, SHA256: actual, SQL: string(body)})
	}
	return catalog, nil
}

func catalogSHA256(catalog []Migration) [32]byte {
	ordered := append([]Migration(nil), catalog...)
	sort.Slice(ordered, func(left, right int) bool { return ordered[left].ID < ordered[right].ID })
	hash := sha256.New()
	var identifier [8]byte
	for _, migration := range ordered {
		binary.BigEndian.PutUint64(identifier[:], migration.ID)
		_, _ = hash.Write(identifier[:])
		_, _ = hash.Write([]byte(migration.Name))
		_, _ = hash.Write([]byte{0})
		_, _ = hash.Write(migration.SHA256[:])
	}
	var result [32]byte
	copy(result[:], hash.Sum(nil))
	return result
}

func mustSHA256(value string) [32]byte {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size {
		panic("invalid embedded migration checksum")
	}
	var result [32]byte
	copy(result[:], decoded)
	return result
}

func migrationCatalogError(cause error) error {
	return newStoreError("MIGRATION_BLOCKED", "migration-catalog", false, cause)
}
