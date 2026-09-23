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
// #33, 0004 to #35, 0005 to #54, 0006 to #76, 0007 to #71, 0008 to #77,
// 0009 to #74, 0010 to #69, 0011 to #104, 0012 to #123, 0013 to #124, and
// 0014 to #107, 0015 to #125, 0016 to #133, 0017 to #106,
// 0018 to #140, 0019 to #117, 0020 to #163, 0021 to #154, 0022 to #115,
// 0023 to #114, and 0024 to #108.

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
	{ID: 6, Name: "0006_declarations_and_plans", SHA256: mustSHA256("463308cf36bd89a84727d5dfea460b17b638f39e19b4a26b5ffd8d2f8b5abcec")},
	{ID: 7, Name: "0007_effective_authorization", SHA256: mustSHA256("0cb4342d94f739b9a0531a44bbd5dfa8f089065975a7d83768f544785cd23e33")},
	{ID: 8, Name: "0008_acknowledgements", SHA256: mustSHA256("49d492dbbab590dfded1b9dea45cce15a6b47ecaf81c25bfcd3767ced0e6c06b")},
	{ID: 9, Name: "0009_runs", SHA256: mustSHA256("27223547d7d7ba1b10c179423fb75ab09c094d892bf4c3a983bb3175be4bd9ab")},
	{ID: 10, Name: "0010_external_executor_leases", SHA256: mustSHA256("8241c954873a85f8fe7e967e2d3ad136d55c32fec8efba06698eda13bc041ff2")},
	{ID: 11, Name: "0011_gate_evidence", SHA256: mustSHA256("fc7a978cbf73eac6f443ae058df6151ce9a9c7d3668520dd528fefbe3944a01a")},
	{ID: 12, Name: "0012_credential_refs", SHA256: mustSHA256("302b2bedb4eee771436e3772c49b3c0c6cdaefbd5a1a17d11370e10a44c8e0c7")},
	{ID: 13, Name: "0013_credential_import_drafts", SHA256: mustSHA256("2dd9895e6a06a6789635cbe787fc89c6c56597f2192b39395ffa5186388e5204")},
	{ID: 14, Name: "0014_audit_chain", SHA256: mustSHA256("11ab59848b8410e6bac8c59101332cf56fd1de96c3a1b89c365df127c70c94d7")},
	{ID: 15, Name: "0015_credential_lifecycle", SHA256: mustSHA256("f5f09a0756ccfd3d6f9686f9e177aba11436fd10d6e98a1b6765fd6c993014e9")},
	{ID: 16, Name: "0016_credential_evidence_hardening", SHA256: mustSHA256("45c41bfd0c9d6e8a5a9b340ea74b0f10cdd8dd4d6beaaa20ea6ad44a3b34a798")},
	{ID: 17, Name: "0017_backup_creation", SHA256: mustSHA256("4ed6f7effbce9174d01d5976179e15309f9bacc1f26b1ead3ac916a2bc1b64d2")},
	{ID: 18, Name: "0018_native_credential_reader_maps", SHA256: mustSHA256("55009c8b750a29c93c184fdbf75db5eb136fb76f78eb9fca2fb46cce1b1f8f90")},
	{ID: 19, Name: "0019_backup_verification", SHA256: mustSHA256("4230197f40c143e60c12eee32306cafb3a532cc052558b5d30d0118665ad792e")},
	{ID: 20, Name: "0020_backup_custody", SHA256: mustSHA256("30d10c219850fdad8ea3a9cd559c0b44806b81592cc592436f85caa099b1decf")},
	{ID: 21, Name: "0021_backup_trust_sources", SHA256: mustSHA256("6eae197a770216dc8bca36b60fb25473f6676d5a341fcb320b5c3444abc9f5b7")},
	{ID: 22, Name: "0022_local_retirements", SHA256: mustSHA256("b36d561f02055342c7166a51c25f41c1acf096023e0714ffab87e28ed8cb55e6")},
	{ID: 23, Name: "0023_offsite_generations", SHA256: mustSHA256("0cfdfbcc3e36776c0fcb4ceae4eccda48e7af8b6b40c03823cdb80cb05b7cb25")},
	{ID: 24, Name: "0024_recovery_authority", SHA256: mustSHA256("404ef0645cb55159faffffc8d6ad120db7302ed62691bd0f4eaf88619ed3cb4f")},
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
