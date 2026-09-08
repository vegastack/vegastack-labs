package store

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"net/url"
	"time"

	"github.com/ncruces/go-sqlite3"
	sqliteDriver "github.com/ncruces/go-sqlite3/driver"
)

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
