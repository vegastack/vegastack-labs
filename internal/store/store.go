package store

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"math"
	"net/url"
	"strings"
	"sync"
	"time"
)

const DefaultBusyTimeout = 5 * time.Second

type Store struct {
	mu         sync.Mutex
	db         *sql.DB
	conn       *sql.Conn
	filesystem FilesystemInspector
	identity   FileIdentity
	writerLock io.Closer
	config     Config
	health     Health
	closed     bool
}

func Open(ctx context.Context, config Config) (*Store, error) {
	if !storePlatformSupported() {
		return nil, newStoreError("UNSUPPORTED_PLATFORM", "database-platform", false, nil)
	}
	config, err := normalizeConfig(config)
	if err != nil {
		return nil, err
	}
	filesystem := config.Filesystem
	if filesystem == nil {
		filesystem = newFilesystemInspector()
	}
	if _, err := filesystem.InspectParent(ctx, config.DatabasePath, config.ExpectedUID); err != nil {
		return nil, err
	}

	var identity FileIdentity
	switch config.Mode {
	case InitializeNew:
		identity, err = filesystem.CreateDatabase(ctx, config.DatabasePath, config.ExpectedUID)
	case OpenExisting:
		identity, err = filesystem.InspectDatabase(ctx, config.DatabasePath, config.ExpectedUID)
	default:
		return nil, newStoreError("INPUT_INVALID", "database-mode", false, nil)
	}
	if err != nil {
		return nil, err
	}

	writerLock, err := filesystem.AcquireWriterLock(ctx, config.DatabasePath, config.ExpectedUID)
	if err != nil {
		return nil, err
	}
	cleanupLock := true
	defer func() {
		if cleanupLock {
			_ = writerLock.Close()
		}
	}()

	database, err := sql.Open(sqliteDriverName, sqliteURI(config.DatabasePath))
	if err != nil {
		return nil, databaseError("INTEGRITY_FAILURE", err)
	}
	database.SetMaxOpenConns(1)
	database.SetMaxIdleConns(1)
	database.SetConnMaxIdleTime(0)
	database.SetConnMaxLifetime(0)
	cleanupDatabase := true
	defer func() {
		if cleanupDatabase {
			_ = database.Close()
		}
	}()

	connection, err := database.Conn(ctx)
	if err != nil {
		return nil, databaseError("INTEGRITY_FAILURE", err)
	}
	cleanupConnection := true
	defer func() {
		if cleanupConnection {
			_ = connection.Close()
		}
	}()

	store := &Store{
		db:         database,
		conn:       connection,
		filesystem: filesystem,
		identity:   identity,
		writerLock: writerLock,
		config:     config,
		health: Health{
			Mode:            DatabaseSafeMode,
			MutationEnabled: false,
			IntegrityStatus: IntegrityUnknown,
			SafeModeReason:  "startup-validation",
		},
	}
	if err := store.configure(ctx); err != nil {
		return nil, err
	}
	if config.Mode == InitializeNew {
		if err := store.applyFoundation(ctx); err != nil {
			return nil, err
		}
	}
	if err := store.readAndValidateState(ctx); err != nil {
		return nil, err
	}
	if err := store.runIntegrityChecks(ctx); err != nil {
		return nil, err
	}
	if syncer, ok := filesystem.(durabilityFilesystem); ok {
		if err := syncer.SyncDatabase(ctx, config.DatabasePath, identity); err != nil {
			return nil, databaseError("INTEGRITY_FAILURE", err)
		}
	} else {
		return nil, databaseError("INTEGRITY_FAILURE", errors.New("durability sync is unavailable"))
	}
	if err := store.checkIdentity(ctx); err != nil {
		return nil, err
	}
	store.health.Mode = DatabaseReady
	store.health.MutationEnabled = true
	store.health.SafeModeReason = ""

	cleanupLock = false
	cleanupDatabase = false
	cleanupConnection = false
	return store, nil
}

func normalizeConfig(config Config) (Config, error) {
	if config.BusyTimeout == 0 {
		config.BusyTimeout = DefaultBusyTimeout
	}
	if config.BusyTimeout < time.Millisecond || config.BusyTimeout > time.Duration(math.MaxInt32)*time.Millisecond {
		return Config{}, newStoreError("INPUT_INVALID", "database-busy-timeout", false, nil)
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	if config.ToolVersion == "" || config.BuildVersion == "" {
		return Config{}, newStoreError("INPUT_INVALID", "database-version", false, nil)
	}
	return config, nil
}

func sqliteURI(databasePath string) string {
	return (&url.URL{Scheme: "file", Path: databasePath, RawQuery: "mode=rw&_txlock=immediate"}).String()
}

func (store *Store) configure(ctx context.Context) error {
	var journalMode string
	if err := store.conn.QueryRowContext(ctx, "PRAGMA journal_mode = DELETE").Scan(&journalMode); err != nil {
		return databaseError("INTEGRITY_FAILURE", err)
	}
	statements := []string{
		"PRAGMA synchronous = FULL",
		"PRAGMA foreign_keys = ON",
		fmt.Sprintf("PRAGMA busy_timeout = %d", store.config.BusyTimeout.Milliseconds()),
	}
	for _, statement := range statements {
		if _, err := store.conn.ExecContext(ctx, statement); err != nil {
			return databaseError("INTEGRITY_FAILURE", err)
		}
	}
	var synchronous, foreignKeys, busyTimeout int
	if err := store.conn.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&journalMode); err != nil {
		return databaseError("INTEGRITY_FAILURE", err)
	}
	if err := store.conn.QueryRowContext(ctx, "PRAGMA synchronous").Scan(&synchronous); err != nil {
		return databaseError("INTEGRITY_FAILURE", err)
	}
	if err := store.conn.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&foreignKeys); err != nil {
		return databaseError("INTEGRITY_FAILURE", err)
	}
	if err := store.conn.QueryRowContext(ctx, "PRAGMA busy_timeout").Scan(&busyTimeout); err != nil {
		return databaseError("INTEGRITY_FAILURE", err)
	}
	if strings.ToLower(journalMode) != "delete" || synchronous != 2 || foreignKeys != 1 || busyTimeout != int(store.config.BusyTimeout.Milliseconds()) {
		return databaseError("INTEGRITY_FAILURE", errors.New("database settings did not hold"))
	}
	return nil
}

func (store *Store) applyFoundation(ctx context.Context) error {
	catalog, err := Catalog()
	if err != nil {
		return err
	}
	if len(catalog) != 1 || catalog[0].ID != 1 {
		return migrationCatalogError(errors.New("foundation migration is unavailable"))
	}
	transaction, err := store.conn.BeginTx(ctx, nil)
	if err != nil {
		return databaseError("INTEGRITY_FAILURE", err)
	}
	defer func() { _ = transaction.Rollback() }()
	migration := catalog[0]
	if _, err := transaction.ExecContext(ctx, migration.SQL); err != nil {
		return databaseError("MIGRATION_BLOCKED", err)
	}
	if _, err := transaction.ExecContext(
		ctx,
		"INSERT INTO schema_migrations(id, name, sha256, applied_at, tool_version, build_version) VALUES (?, ?, ?, ?, ?, ?)",
		migration.ID,
		migration.Name,
		migration.SHA256[:],
		store.config.Clock().UTC().Format(time.RFC3339Nano),
		store.config.ToolVersion,
		store.config.BuildVersion,
	); err != nil {
		return databaseError("MIGRATION_BLOCKED", err)
	}
	if err := transaction.Commit(); err != nil {
		return databaseError("INTEGRITY_FAILURE", err)
	}
	return nil
}

func (store *Store) readAndValidateState(ctx context.Context) error {
	var schemaVersion, stateRevision, recoveryEpoch int64
	if err := store.conn.QueryRowContext(ctx, "SELECT schema_version, state_revision, recovery_epoch FROM system_meta WHERE id = 1").Scan(&schemaVersion, &stateRevision, &recoveryEpoch); err != nil {
		return databaseError("INTEGRITY_FAILURE", err)
	}
	if schemaVersion < 0 || stateRevision < 0 || recoveryEpoch < 0 {
		return databaseError("INTEGRITY_FAILURE", errors.New("negative store metadata"))
	}
	catalog, err := Catalog()
	if err != nil {
		return err
	}
	if uint64(schemaVersion) > uint64(len(catalog)) {
		return databaseError("VERSION_INCOMPATIBLE", errors.New("schema is newer than this binary"))
	}
	rows, err := store.conn.QueryContext(ctx, "SELECT id, name, sha256 FROM schema_migrations ORDER BY id")
	if err != nil {
		return databaseError("MIGRATION_BLOCKED", err)
	}
	defer rows.Close()
	index := 0
	for rows.Next() {
		var id uint64
		var name string
		var checksum []byte
		if err := rows.Scan(&id, &name, &checksum); err != nil {
			return databaseError("MIGRATION_BLOCKED", err)
		}
		if index >= len(catalog) || id != catalog[index].ID || name != catalog[index].Name || !bytes.Equal(checksum, catalog[index].SHA256[:]) {
			return databaseError("MIGRATION_BLOCKED", errors.New("migration ledger differs"))
		}
		index++
	}
	if err := rows.Err(); err != nil {
		return databaseError("MIGRATION_BLOCKED", err)
	}
	if index != int(schemaVersion) {
		return databaseError("MIGRATION_BLOCKED", errors.New("migration ledger is incomplete"))
	}
	var sqliteVersion string
	if err := store.conn.QueryRowContext(ctx, "SELECT sqlite_version()").Scan(&sqliteVersion); err != nil {
		return databaseError("INTEGRITY_FAILURE", err)
	}
	store.health.SchemaVersion = uint64(schemaVersion)
	store.health.SQLiteVersion = sqliteVersion
	store.health.Revision = RevisionToken{StateRevision: stateRevision, RecoveryEpoch: recoveryEpoch}
	return nil
}

func (store *Store) runIntegrityChecks(ctx context.Context) error {
	rows, err := store.conn.QueryContext(ctx, "PRAGMA foreign_key_check")
	if err != nil {
		return databaseError("INTEGRITY_FAILURE", err)
	}
	foreignKeyFailure := rows.Next()
	rowsErr := rows.Err()
	closeErr := rows.Close()
	if foreignKeyFailure || rowsErr != nil || closeErr != nil {
		return databaseError("INTEGRITY_FAILURE", errors.New("foreign-key check failed"))
	}
	var integrity string
	if err := store.conn.QueryRowContext(ctx, "PRAGMA integrity_check(1)").Scan(&integrity); err != nil || integrity != "ok" {
		return databaseError("INTEGRITY_FAILURE", errors.New("integrity check failed"))
	}
	now := store.config.Clock().UTC()
	store.health.LastIntegrityCheckAt = &now
	store.health.IntegrityStatus = IntegrityVerified
	return nil
}

func (store *Store) checkIdentity(ctx context.Context) error {
	actual, err := store.filesystem.InspectDatabase(ctx, store.config.DatabasePath, store.config.ExpectedUID)
	if err != nil || !store.filesystem.SameFile(store.identity, actual) {
		store.enterSafeMode("unsafe-file-identity")
		if err == nil {
			err = errors.New("database identity changed")
		}
		return databaseError("INTEGRITY_FAILURE", err)
	}
	return nil
}

func (store *Store) enterSafeMode(reason string) {
	store.health.Mode = DatabaseSafeMode
	store.health.MutationEnabled = false
	store.health.SafeModeReason = reason
	store.health.IntegrityStatus = IntegrityFailed
}

func (store *Store) Health(ctx context.Context) (Health, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closed {
		return Health{}, newStoreError("DEPENDENCY_UNAVAILABLE", "database", false, nil)
	}
	if err := store.checkIdentity(ctx); err != nil {
		return store.health, err
	}
	return store.health, nil
}

func (store *Store) Close() error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closed {
		return nil
	}
	store.closed = true
	var first error
	if store.conn != nil {
		if err := store.conn.Close(); err != nil {
			first = databaseError("INTEGRITY_FAILURE", err)
		}
	}
	if store.db != nil {
		if err := store.db.Close(); err != nil && first == nil {
			first = databaseError("INTEGRITY_FAILURE", err)
		}
	}
	if store.writerLock != nil {
		if err := store.writerLock.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func databaseError(code string, cause error) error {
	if Code(cause) != "" {
		return cause
	}
	return newStoreError(code, "database", false, cause)
}
