package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"io"
	"net/url"
	"os"
	"time"

	"github.com/ncruces/go-sqlite3"
	sqliteDriver "github.com/ncruces/go-sqlite3/driver"
)

// NewOnlineSnapshotSource exposes the store-owned read-only online snapshot port
// used by the backup capture seam. The returned source shares the single store
// SQLite owner; it never opens a second writable connection to the database.
func NewOnlineSnapshotSource(authority *Store) (OnlineSnapshotSource, error) {
	if authority == nil {
		return nil, newStoreError("INPUT_INVALID", "backup-capture", false, nil)
	}
	catalog, err := Catalog()
	if err != nil {
		return nil, err
	}
	return &recoverySource{store: authority, catalog: catalog}, nil
}

func NewRestoredSQLiteInspector(authority *Store) (RestoredSQLiteInspector, error) {
	if authority == nil {
		return nil, newStoreError("INPUT_INVALID", "backup-restored-inspector", false, nil)
	}
	catalog, err := Catalog()
	if err != nil {
		return nil, err
	}
	return &recoverySource{store: authority, catalog: catalog}, nil
}

// CurrentExpectation reads the live database's current schema version, state
// revision, recovery epoch and migration-catalog digest. Binding this to a
// capture lets OnlineSnapshot reject any concurrent mutation.
func (source *recoverySource) CurrentExpectation(ctx context.Context) (SnapshotExpectation, error) {
	if source == nil || source.store == nil || len(source.catalog) == 0 {
		return SnapshotExpectation{}, newStoreError("INPUT_INVALID", "backup-capture", false, nil)
	}
	var expectation SnapshotExpectation
	err := source.store.Read(ctx, func(tx ReadTx) error {
		return tx.queryRow(ctx, `SELECT schema_version, state_revision, recovery_epoch FROM system_meta WHERE id = 1`).Scan(&expectation.SchemaVersion, &expectation.Revision.StateRevision, &expectation.Revision.RecoveryEpoch)
	})
	if err != nil {
		return SnapshotExpectation{}, err
	}
	expectation.CatalogSHA256 = catalogSHA256(source.catalog)
	return expectation, nil
}

// OnlineSnapshot produces one consistent read-only snapshot of the live control
// database and verifies it before returning a secret-free description. It never
// exposes the live database file and returns no snapshot on any failure.
func (source *recoverySource) OnlineSnapshot(ctx context.Context, request OnlineSnapshotRequest) (OnlineSnapshotResult, error) {
	if source == nil || source.store == nil || request.Destination == "" || request.Destination == source.store.config.DatabasePath {
		return OnlineSnapshotResult{}, newStoreError("INPUT_INVALID", "backup-capture", false, nil)
	}
	if err := source.OnlineBackup(ctx, request.Destination, BackupStepPolicy{PagesPerStep: 128, BusyBudget: request.BusyBudget}); err != nil {
		return OnlineSnapshotResult{}, err
	}
	inspection, err := source.InspectSnapshot(ctx, request.Destination, request.Expected)
	if err != nil {
		return OnlineSnapshotResult{}, err
	}
	if inspection.IntegrityStatus != IntegrityVerified {
		return OnlineSnapshotResult{}, newStoreError("INTEGRITY_FAILURE", "backup-capture", false, nil)
	}
	digest, size, err := hashSnapshotFile(request.Destination)
	if err != nil {
		return OnlineSnapshotResult{}, databaseError("INTEGRITY_FAILURE", err)
	}
	return OnlineSnapshotResult{
		SQLiteVersion:  inspection.SQLiteVersion,
		SchemaVersion:  inspection.SchemaVersion,
		Revision:       inspection.Revision,
		CatalogSHA256:  request.Expected.CatalogSHA256,
		DatabaseSHA256: digest,
		Bytes:          size,
	}, nil
}

func hashSnapshotFile(path string) ([32]byte, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return [32]byte{}, 0, err
	}
	defer file.Close()
	hasher := sha256.New()
	size, err := io.Copy(hasher, file)
	if err != nil {
		return [32]byte{}, 0, err
	}
	var digest [32]byte
	copy(digest[:], hasher.Sum(nil))
	return digest, size, nil
}

type recoverySource struct {
	store   *Store
	catalog []Migration
}

func (source *recoverySource) OnlineBackup(ctx context.Context, destination string, policy BackupStepPolicy) error {
	if source == nil || source.store == nil || destination == source.store.config.DatabasePath {
		return newStoreError("INPUT_INVALID", "migration-snapshot", false, nil)
	}
	if policy.PagesPerStep <= 0 {
		policy.PagesPerStep = 64
	}
	if policy.BusyBudget <= 0 {
		policy.BusyBudget = source.store.config.BusyTimeout
	}
	identity, err := source.store.filesystem.CreateDatabase(ctx, destination, source.store.config.ExpectedUID)
	if err != nil {
		return err
	}
	backupErr := source.store.conn.Raw(func(driverConnection any) error {
		connection, ok := driverConnection.(sqliteDriver.Conn)
		if !ok {
			return errors.New("sqlite driver connection is unavailable")
		}
		backup, err := connection.Raw().BackupInit("main", fileURI(destination, "rw"))
		if err != nil {
			return err
		}
		closed := false
		defer func() {
			if !closed {
				_ = backup.Close()
			}
		}()
		deadline := time.Now().Add(policy.BusyBudget)
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			done, stepErr := backup.Step(policy.PagesPerStep)
			if stepErr == nil && done {
				closeErr := backup.Close()
				closed = true
				return closeErr
			}
			if stepErr == nil {
				continue
			}
			if (errors.Is(stepErr, sqlite3.BUSY) || errors.Is(stepErr, sqlite3.LOCKED)) && time.Now().Before(deadline) {
				timer := time.NewTimer(time.Millisecond)
				select {
				case <-ctx.Done():
					timer.Stop()
					return ctx.Err()
				case <-timer.C:
					continue
				}
			}
			return stepErr
		}
	})
	if backupErr != nil {
		return classifySQLiteError(ctx, backupErr)
	}
	if syncer, ok := source.store.filesystem.(durabilityFilesystem); !ok {
		return databaseError("INTEGRITY_FAILURE", errors.New("snapshot durability sync is unavailable"))
	} else if err := syncer.SyncDatabase(ctx, destination, identity); err != nil {
		return databaseError("INTEGRITY_FAILURE", err)
	}
	return nil
}

func (source *recoverySource) InspectSnapshot(ctx context.Context, snapshotPath string, expected SnapshotExpectation) (SnapshotInspection, error) {
	if source == nil || source.store == nil || snapshotPath == source.store.config.DatabasePath {
		return SnapshotInspection{}, newStoreError("INPUT_INVALID", "migration-snapshot", false, nil)
	}
	if _, err := source.store.filesystem.InspectDatabase(ctx, snapshotPath, source.store.config.ExpectedUID); err != nil {
		return SnapshotInspection{}, err
	}
	database, err := sql.Open(sqliteDriverName, fileURI(snapshotPath, "ro"))
	if err != nil {
		return SnapshotInspection{}, databaseError("INTEGRITY_FAILURE", err)
	}
	database.SetMaxOpenConns(1)
	defer database.Close()
	inspection := SnapshotInspection{IntegrityStatus: IntegrityUnknown}
	if err := database.QueryRowContext(ctx, `SELECT sqlite_version()`).Scan(&inspection.SQLiteVersion); err != nil {
		return SnapshotInspection{}, databaseError("INTEGRITY_FAILURE", err)
	}
	if err := database.QueryRowContext(ctx, `SELECT schema_version, state_revision, recovery_epoch FROM system_meta WHERE id = 1`).Scan(&inspection.SchemaVersion, &inspection.Revision.StateRevision, &inspection.Revision.RecoveryEpoch); err != nil {
		return SnapshotInspection{}, databaseError("INTEGRITY_FAILURE", err)
	}
	if len(source.catalog) == 0 || catalogSHA256(source.catalog) != expected.CatalogSHA256 {
		return SnapshotInspection{}, newStoreError("MIGRATION_BLOCKED", "migration-snapshot", false, nil)
	}
	rows, err := database.QueryContext(ctx, `SELECT id, name, sha256 FROM schema_migrations ORDER BY id`)
	if err != nil {
		return SnapshotInspection{}, databaseError("INTEGRITY_FAILURE", err)
	}
	count := uint64(0)
	for rows.Next() {
		var id uint64
		var name string
		var checksum []byte
		if err := rows.Scan(&id, &name, &checksum); err != nil || id != count+1 || id > uint64(len(source.catalog)) || source.catalog[id-1].Name != name || !bytes.Equal(source.catalog[id-1].SHA256[:], checksum) {
			_ = rows.Close()
			return SnapshotInspection{}, newStoreError("MIGRATION_BLOCKED", "migration-snapshot", false, err)
		}
		count++
	}
	rowsErr := rows.Err()
	closeErr := rows.Close()
	if rowsErr != nil || closeErr != nil || count != inspection.SchemaVersion {
		return SnapshotInspection{}, newStoreError("MIGRATION_BLOCKED", "migration-snapshot", false, errors.New("snapshot migration ledger is incomplete"))
	}
	foreignKeys, err := database.QueryContext(ctx, `PRAGMA foreign_key_check`)
	if err != nil {
		return SnapshotInspection{}, databaseError("INTEGRITY_FAILURE", err)
	}
	foreignKeyFailure := foreignKeys.Next()
	foreignKeyRowsErr := foreignKeys.Err()
	foreignKeyCloseErr := foreignKeys.Close()
	if foreignKeyFailure || foreignKeyRowsErr != nil || foreignKeyCloseErr != nil {
		return SnapshotInspection{}, databaseError("INTEGRITY_FAILURE", errors.New("snapshot foreign-key check failed"))
	}
	var integrity string
	if err := database.QueryRowContext(ctx, `PRAGMA integrity_check(1)`).Scan(&integrity); err != nil || integrity != "ok" {
		return SnapshotInspection{}, databaseError("INTEGRITY_FAILURE", errors.New("snapshot integrity check failed"))
	}
	if inspection.SchemaVersion != expected.SchemaVersion || inspection.Revision != expected.Revision {
		return SnapshotInspection{}, newStoreError("MIGRATION_BLOCKED", "migration-snapshot", false, nil)
	}
	inspection.IntegrityStatus = IntegrityVerified
	return inspection, nil
}

func (source *recoverySource) RestoreSnapshot(ctx context.Context, snapshotPath, isolatedTarget string) error {
	if source == nil || source.store == nil || snapshotPath == source.store.config.DatabasePath || isolatedTarget == source.store.config.DatabasePath || snapshotPath == isolatedTarget {
		return newStoreError("INPUT_INVALID", "migration-restore", false, nil)
	}
	if _, err := source.store.filesystem.InspectDatabase(ctx, snapshotPath, source.store.config.ExpectedUID); err != nil {
		return err
	}
	identity, err := source.store.filesystem.CreateDatabase(ctx, isolatedTarget, source.store.config.ExpectedUID)
	if err != nil {
		return err
	}
	database, err := sql.Open(sqliteDriverName, fileURI(isolatedTarget, "rw"))
	if err != nil {
		return databaseError("INTEGRITY_FAILURE", err)
	}
	database.SetMaxOpenConns(1)
	defer database.Close()
	connection, err := database.Conn(ctx)
	if err != nil {
		return databaseError("INTEGRITY_FAILURE", err)
	}
	defer connection.Close()
	if err := connection.Raw(func(driverConnection any) error {
		raw, ok := driverConnection.(sqliteDriver.Conn)
		if !ok {
			return errors.New("sqlite driver connection is unavailable")
		}
		return raw.Raw().Restore("main", fileURI(snapshotPath, "ro"))
	}); err != nil {
		return classifySQLiteError(ctx, err)
	}
	if syncer, ok := source.store.filesystem.(durabilityFilesystem); !ok {
		return databaseError("INTEGRITY_FAILURE", errors.New("restore durability sync is unavailable"))
	} else if err := syncer.SyncDatabase(ctx, isolatedTarget, identity); err != nil {
		return databaseError("INTEGRITY_FAILURE", err)
	}
	return nil
}

func fileURI(path, mode string) string {
	return (&url.URL{Scheme: "file", Path: path, RawQuery: "mode=" + mode}).String()
}

var _ MigrationSource = (*recoverySource)(nil)
