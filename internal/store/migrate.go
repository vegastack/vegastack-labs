package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

func (store *Store) migrate(ctx context.Context, catalog []Migration) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	err := store.migrateLocked(ctx, catalog)
	if err != nil && store.health.Mode != DatabaseSafeMode {
		store.migrationSafeMode("migration-blocked")
	}
	return err
}

func (store *Store) migrateLocked(ctx context.Context, catalog []Migration) error {
	if err := validateMigrationCatalog(catalog); err != nil {
		return err
	}
	currentSchema, currentRevision, err := store.validateAppliedPrefix(ctx, catalog)
	if err != nil {
		return err
	}
	if currentSchema == uint64(len(catalog)) {
		return nil
	}
	if store.config.Recovery == nil {
		return newStoreError("MIGRATION_BLOCKED", "migration-recovery", false, nil)
	}
	request := MigrationRequest{
		Purpose:              "pre-migration-recovery",
		ToolVersion:          store.config.ToolVersion,
		BuildVersion:         store.config.BuildVersion,
		CurrentSchemaVersion: currentSchema,
		TargetSchemaVersion:  uint64(len(catalog)),
		CatalogSHA256:        catalogSHA256(catalog),
		CurrentRevision:      currentRevision,
		BusyBudget:           store.config.BusyTimeout,
		RequestedAt:          store.config.Clock().UTC(),
	}
	source := &recoverySource{store: store}
	snapshot, err := store.config.Recovery.Prepare(ctx, source, request)
	if err != nil || snapshot.SnapshotID == "" || snapshot.SchemaVersion != currentSchema || snapshot.Revision != currentRevision || snapshot.CatalogSHA256 != request.CatalogSHA256 {
		if err == nil {
			err = errors.New("verified snapshot does not bind migration state")
		}
		return newStoreError("MIGRATION_BLOCKED", "migration-recovery", false, err)
	}

	transaction, err := store.conn.BeginTx(ctx, nil)
	if err != nil {
		return store.failMigration(ctx, source, snapshot, store.transactionError(ctx, err))
	}
	committed := false
	defer func() {
		if !committed {
			_ = transaction.Rollback()
		}
	}()
	for _, migration := range catalog[currentSchema:] {
		if _, err := transaction.ExecContext(ctx, migration.SQL); err != nil {
			_ = transaction.Rollback()
			return store.failMigration(ctx, source, snapshot, newStoreError("MIGRATION_BLOCKED", "migration-apply", false, err))
		}
		if _, err := transaction.ExecContext(ctx,
			`INSERT INTO schema_migrations(id, name, sha256, applied_at, tool_version, build_version) VALUES (?, ?, ?, ?, ?, ?)`,
			migration.ID, migration.Name, migration.SHA256[:], store.config.Clock().UTC().Format(time.RFC3339Nano), store.config.ToolVersion, store.config.BuildVersion,
		); err != nil {
			_ = transaction.Rollback()
			return store.failMigration(ctx, source, snapshot, newStoreError("MIGRATION_BLOCKED", "migration-ledger", false, err))
		}
	}
	result, err := transaction.ExecContext(ctx, `UPDATE system_meta SET schema_version = ? WHERE id = 1 AND schema_version = ? AND state_revision = ? AND recovery_epoch = ?`, len(catalog), currentSchema, currentRevision.StateRevision, currentRevision.RecoveryEpoch)
	if err != nil {
		_ = transaction.Rollback()
		return store.failMigration(ctx, source, snapshot, newStoreError("MIGRATION_BLOCKED", "migration-version", false, err))
	}
	if rows, rowsErr := result.RowsAffected(); rowsErr != nil || rows != 1 {
		if rowsErr == nil {
			rowsErr = errors.New("migration version guard did not match")
		}
		_ = transaction.Rollback()
		return store.failMigration(ctx, source, snapshot, newStoreError("MIGRATION_BLOCKED", "migration-version", false, rowsErr))
	}
	if err := checkTransactionIntegrity(ctx, transaction); err != nil {
		_ = transaction.Rollback()
		return store.failMigration(ctx, source, snapshot, err)
	}
	if err := store.checkIdentity(ctx); err != nil {
		_ = transaction.Rollback()
		return store.failMigration(ctx, source, snapshot, err)
	}
	if store.beforeCommit != nil {
		if err := store.beforeCommit(); err != nil {
			_ = transaction.Rollback()
			return store.failMigration(ctx, source, snapshot, databaseError("INTEGRITY_FAILURE", err))
		}
	}
	if err := transaction.Commit(); err != nil {
		return store.failMigration(ctx, source, snapshot, store.transactionError(ctx, err))
	}
	committed = true
	if syncer, ok := store.filesystem.(durabilityFilesystem); !ok {
		return store.failMigration(ctx, source, snapshot, databaseError("INTEGRITY_FAILURE", errors.New("durability sync is unavailable")))
	} else if err := syncer.SyncDatabase(ctx, store.config.DatabasePath, store.identity); err != nil {
		return store.failMigration(ctx, source, snapshot, databaseError("INTEGRITY_FAILURE", err))
	}
	store.health.SchemaVersion = uint64(len(catalog))
	store.health.RecoveryPending = false
	return nil
}

func validateMigrationCatalog(catalog []Migration) error {
	if len(catalog) == 0 {
		return migrationCatalogError(errors.New("catalog is empty"))
	}
	for index, migration := range catalog {
		if migration.ID != uint64(index+1) || !migrationNamePattern.MatchString(migration.Name) || migration.Name[:4] != fmt.Sprintf("%04d", migration.ID) || migration.SHA256 != sha256.Sum256([]byte(migration.SQL)) {
			return migrationCatalogError(errors.New("catalog sequence or checksum is invalid"))
		}
	}
	return nil
}

func (store *Store) validateAppliedPrefix(ctx context.Context, catalog []Migration) (uint64, RevisionToken, error) {
	var schema uint64
	var revision RevisionToken
	if err := store.conn.QueryRowContext(ctx, `SELECT schema_version, state_revision, recovery_epoch FROM system_meta WHERE id = 1`).Scan(&schema, &revision.StateRevision, &revision.RecoveryEpoch); err != nil {
		return 0, RevisionToken{}, databaseError("INTEGRITY_FAILURE", err)
	}
	if schema > uint64(len(catalog)) {
		return 0, RevisionToken{}, newStoreError("VERSION_INCOMPATIBLE", "database-schema", false, nil)
	}
	rows, err := store.conn.QueryContext(ctx, `SELECT id, name, sha256 FROM schema_migrations ORDER BY id`)
	if err != nil {
		return 0, RevisionToken{}, newStoreError("MIGRATION_BLOCKED", "migration-ledger", false, err)
	}
	defer rows.Close()
	count := uint64(0)
	for rows.Next() {
		var id uint64
		var name string
		var checksum []byte
		if err := rows.Scan(&id, &name, &checksum); err != nil {
			return 0, RevisionToken{}, newStoreError("MIGRATION_BLOCKED", "migration-ledger", false, err)
		}
		if count >= schema || id != count+1 || id > uint64(len(catalog)) || catalog[id-1].Name != name || !bytes.Equal(catalog[id-1].SHA256[:], checksum) {
			return 0, RevisionToken{}, newStoreError("MIGRATION_BLOCKED", "migration-ledger", false, nil)
		}
		count++
	}
	if err := rows.Err(); err != nil || count != schema {
		return 0, RevisionToken{}, newStoreError("MIGRATION_BLOCKED", "migration-ledger", false, err)
	}
	return schema, revision, nil
}

func checkTransactionIntegrity(ctx context.Context, transaction *sql.Tx) error {
	rows, err := transaction.QueryContext(ctx, `PRAGMA foreign_key_check`)
	if err != nil {
		return databaseError("INTEGRITY_FAILURE", err)
	}
	failed := rows.Next()
	rowsErr := rows.Err()
	closeErr := rows.Close()
	if failed || rowsErr != nil || closeErr != nil {
		return databaseError("INTEGRITY_FAILURE", errors.New("migration foreign-key check failed"))
	}
	var result string
	if err := transaction.QueryRowContext(ctx, `PRAGMA integrity_check(1)`).Scan(&result); err != nil || result != "ok" {
		return databaseError("INTEGRITY_FAILURE", errors.New("migration integrity check failed"))
	}
	return nil
}

func (store *Store) failMigration(ctx context.Context, source MigrationSource, snapshot VerifiedSnapshot, original error) error {
	store.migrationSafeMode("migration-failure")
	_, _ = store.config.Recovery.VerifyRestorable(ctx, source, snapshot)
	return original
}
