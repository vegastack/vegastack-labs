//go:build linux

package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

type credentialMigrationRecovery struct {
	snapshot, restored string
	source             MigrationSource
	verified           VerifiedSnapshot
}

func (recovery *credentialMigrationRecovery) Prepare(ctx context.Context, source MigrationSource, request MigrationRequest) (VerifiedSnapshot, error) {
	recovery.source = source
	if err := source.OnlineBackup(ctx, recovery.snapshot, BackupStepPolicy{PagesPerStep: 1}); err != nil {
		return VerifiedSnapshot{}, err
	}
	expected := SnapshotExpectation{SchemaVersion: request.CurrentSchemaVersion, Revision: request.CurrentRevision, CatalogSHA256: request.CatalogSHA256}
	if _, err := source.InspectSnapshot(ctx, recovery.snapshot, expected); err != nil {
		return VerifiedSnapshot{}, err
	}
	recovery.verified = VerifiedSnapshot{SnapshotID: recovery.snapshot, SchemaVersion: expected.SchemaVersion, Revision: expected.Revision, CatalogSHA256: expected.CatalogSHA256}
	return recovery.verified, nil
}

func (recovery *credentialMigrationRecovery) VerifyRestorable(ctx context.Context, source MigrationSource, snapshot VerifiedSnapshot) (RestoreEvidence, error) {
	if err := source.RestoreSnapshot(ctx, snapshot.SnapshotID, recovery.restored); err != nil {
		return RestoreEvidence{}, err
	}
	if _, err := source.InspectSnapshot(ctx, recovery.restored, SnapshotExpectation{SchemaVersion: snapshot.SchemaVersion, Revision: snapshot.Revision, CatalogSHA256: snapshot.CatalogSHA256}); err != nil {
		return RestoreEvidence{}, err
	}
	return RestoreEvidence{SnapshotID: snapshot.SnapshotID, Status: "verified", SchemaVersion: snapshot.SchemaVersion, Revision: snapshot.Revision}, nil
}

func TestCredentialMigrationAppliesAfterRestorablePreMigrationSnapshot(t *testing.T) {
	config := testConfig(t)
	catalog, err := Catalog()
	if err != nil {
		t.Fatal(err)
	}
	if len(catalog) != 13 || catalog[11].ID != 12 || catalog[11].Name != "0012_credential_refs" || catalog[12].ID != 13 || catalog[12].Name != "0013_credential_import_drafts" {
		t.Fatalf("fresh migration catalog: %#v", catalog)
	}
	file, err := os.OpenFile(config.DatabasePath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	database, err := sql.Open(sqliteDriverName, sqliteURI(config.DatabasePath))
	if err != nil {
		t.Fatal(err)
	}
	transaction, err := database.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, migration := range catalog[:11] {
		if _, err := transaction.ExecContext(context.Background(), migration.SQL); err != nil {
			t.Fatal(err)
		}
		if _, err := transaction.ExecContext(context.Background(), `INSERT INTO schema_migrations(id,name,sha256,applied_at,tool_version,build_version) VALUES(?,?,?,?,?,?)`, migration.ID, migration.Name, migration.SHA256[:], time.Now().UTC().Format(time.RFC3339Nano), config.ToolVersion, config.BuildVersion); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := transaction.ExecContext(context.Background(), `UPDATE system_meta SET schema_version=11 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if _, err := transaction.ExecContext(context.Background(), `CREATE TABLE credential_migration_sentinel(value TEXT NOT NULL) STRICT; INSERT INTO credential_migration_sentinel(value) VALUES('pre-0012')`); err != nil {
		t.Fatal(err)
	}
	if err := transaction.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	recovery := &credentialMigrationRecovery{snapshot: filepath.Join(filepath.Dir(config.DatabasePath), "credential-pre-0012.db"), restored: filepath.Join(filepath.Dir(config.DatabasePath), "credential-isolated-restore.db")}
	config.Mode, config.Recovery = OpenExisting, recovery
	authority, err := Open(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = authority.Close() })
	if recovery.source == nil || recovery.verified.SchemaVersion != 11 {
		t.Fatal("pre-migration backup was not prepared")
	}
	if _, err := recovery.VerifyRestorable(context.Background(), recovery.source, recovery.verified); err != nil {
		t.Fatal(err)
	}
	old, err := sql.Open(sqliteDriverName, fileURI(recovery.restored, "ro"))
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	var sentinel string
	if err := old.QueryRowContext(context.Background(), `SELECT value FROM credential_migration_sentinel`).Scan(&sentinel); err != nil || sentinel != "pre-0012" {
		t.Fatalf("restore lost pre-migration state: %s %v", sentinel, err)
	}
	var tableCount int
	if err := old.QueryRowContext(context.Background(), `SELECT count(*) FROM sqlite_schema WHERE type='table' AND name='credential_reference_versions'`).Scan(&tableCount); err != nil || tableCount != 0 {
		t.Fatalf("pre-0012 snapshot polluted: %d %v", tableCount, err)
	}
	if err := authority.conn.QueryRowContext(context.Background(), `SELECT count(*) FROM sqlite_schema WHERE type='table' AND name='credential_reference_versions'`).Scan(&tableCount); err != nil || tableCount != 1 {
		t.Fatalf("0012 not applied: %d %v", tableCount, err)
	}
}

func TestCredentialImportMigrationAppliesAfterRestorablePre0013Snapshot(t *testing.T) {
	config := testConfig(t)
	catalog, err := Catalog()
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(config.DatabasePath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	database, err := sql.Open(sqliteDriverName, sqliteURI(config.DatabasePath))
	if err != nil {
		t.Fatal(err)
	}
	transaction, err := database.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, migration := range catalog[:12] {
		if _, err := transaction.ExecContext(context.Background(), migration.SQL); err != nil {
			t.Fatal(err)
		}
		if _, err := transaction.ExecContext(context.Background(), `INSERT INTO schema_migrations(id,name,sha256,applied_at,tool_version,build_version) VALUES(?,?,?,?,?,?)`, migration.ID, migration.Name, migration.SHA256[:], time.Now().UTC().Format(time.RFC3339Nano), config.ToolVersion, config.BuildVersion); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := transaction.ExecContext(context.Background(), `UPDATE system_meta SET schema_version=12 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if _, err := transaction.ExecContext(context.Background(), `CREATE TABLE credential_import_migration_sentinel(value TEXT NOT NULL) STRICT; INSERT INTO credential_import_migration_sentinel(value) VALUES('pre-0013')`); err != nil {
		t.Fatal(err)
	}
	if err := transaction.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	recovery := &credentialMigrationRecovery{snapshot: filepath.Join(filepath.Dir(config.DatabasePath), "credential-pre-0013.db"), restored: filepath.Join(filepath.Dir(config.DatabasePath), "credential-pre-0013-isolated-restore.db")}
	config.Mode, config.Recovery = OpenExisting, recovery
	authority, err := Open(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = authority.Close() })
	if recovery.source == nil || recovery.verified.SchemaVersion != 12 {
		t.Fatal("pre-0013 backup was not prepared")
	}
	if _, err := recovery.VerifyRestorable(context.Background(), recovery.source, recovery.verified); err != nil {
		t.Fatal(err)
	}
	old, err := sql.Open(sqliteDriverName, fileURI(recovery.restored, "ro"))
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	var sentinel string
	if err := old.QueryRowContext(context.Background(), `SELECT value FROM credential_import_migration_sentinel`).Scan(&sentinel); err != nil || sentinel != "pre-0013" {
		t.Fatalf("restore lost pre-0013 state: %s %v", sentinel, err)
	}
	var tableCount int
	if err := old.QueryRowContext(context.Background(), `SELECT count(*) FROM sqlite_schema WHERE type='table' AND name='credential_import_drafts'`).Scan(&tableCount); err != nil || tableCount != 0 {
		t.Fatalf("pre-0013 snapshot polluted: %d %v", tableCount, err)
	}
	if err := authority.conn.QueryRowContext(context.Background(), `SELECT count(*) FROM sqlite_schema WHERE type='table' AND name='credential_import_drafts'`).Scan(&tableCount); err != nil || tableCount != 1 {
		t.Fatalf("0013 not applied: %d %v", tableCount, err)
	}
}

func TestCredentialBindingStageRequiresMatchingDraftAndStoredPlan(t *testing.T) {
	repository := openCredentialStore(t)
	binding := credentialBindingFixture()
	binding.StateRevision = 3 // draft + binding stage + exact plan commit
	draft := validDeclarationStoreRequest()
	draft.Document.DeclarationID = "declaration-a"
	draft.Document.Operations[0].OperationID = binding.OperationID
	draft.Document.Operations[0].AdapterID = binding.AdapterID
	draft.Document.Operations[0].TargetID = binding.TargetID
	draft.Document.Operations[0].InputDigest = credentialref.OperationManifestDigest([]credentialref.StepBinding{binding}, binding.OperationID)
	draft.Document.Extensions = []generated.ContractExtension{{Name: "x-credential-bindings", ValueDigest: credentialref.ManifestDigest([]credentialref.StepBinding{binding})}}
	draft.Document.ContentDigest = declarationContentDigest(draft.Document, draft.ReasonDigest)
	if _, err := NewDeclarationRepository(repository.store).CreateRevision(context.Background(), draft); err != nil {
		t.Fatal(err)
	}
	stage := CredentialBindingStageRequest{DeclarationID: draft.Document.DeclarationID, DeclarationRevision: draft.Document.Revision, Bindings: []credentialref.StepBinding{binding}, Expected: RevisionToken{StateRevision: 1, RecoveryEpoch: 0}, Attribution: draft.Attribution, KeyDigest: testDigest, RequestDigest: testDigest}
	wrong := stage
	wrong.Bindings = []credentialref.StepBinding{binding}
	wrong.Bindings[0].PurposeID = "other-purpose"
	if _, err := repository.StageStepBindings(context.Background(), wrong); err == nil {
		t.Fatal("mismatched manifest staged")
	}
	if _, err := repository.StageStepBindings(context.Background(), stage); err != nil {
		t.Fatal(err)
	}
	plan := planWithoutCredentialExtension()
	plan.Binding.DeclarationRevision = draft.Document.Revision + 1
	plan.Extensions = draft.Document.Extensions
	plan.Operations[0].InputDigest = draft.Document.Operations[0].InputDigest
	if _, err := repository.GetStepBindings(context.Background(), plan, binding.OperationID); err == nil {
		t.Fatal("forged unstored plan read credential binding")
	}
	commit := validPlanStoreRequest(draft.Document)
	commit.Expected.StateRevision = 2
	commit.DesiredDeclaration.StateRevision = 3
	commit.Plan.Binding.PriorStateRevision = 2
	commit.Plan.Binding.StateRevision = 3
	commit.Plan.Operations[0].OperationID = binding.OperationID
	commit.Plan.Operations[0].AdapterID = binding.AdapterID
	commit.Plan.Operations[0].TargetID = binding.TargetID
	commit.Plan.Operations[0].InputDigest = draft.Document.Operations[0].InputDigest
	commit.Plan.Extensions = draft.Document.Extensions
	commit.DesiredDeclaration.Extensions = draft.Document.Extensions
	commit.Plan.PlanID, commit.Plan.PlanDigest = "", ""
	preimage, err := json.Marshal(commit.Plan)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(preimage)
	commit.Plan.PlanDigest = "sha256:" + hex.EncodeToString(sum[:])
	commit.Plan.PlanID = "plan-" + hex.EncodeToString(sum[:16])
	commit.CanonicalBytes, err = json.Marshal(commit.Plan)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewPlanRepository(repository.store).CommitDeclarationAndPlan(context.Background(), commit); err != nil {
		t.Fatal(err)
	}
	selected, err := repository.GetStepBindings(context.Background(), commit.Plan, binding.OperationID)
	if err != nil || len(selected) != 1 || selected[0].Digest() != binding.Digest() {
		t.Fatalf("stored binding not sealed: %v %#v", err, selected)
	}
	changed := commit.Plan
	changed.Operations = append([]generated.PlanOperation(nil), changed.Operations...)
	changed.Operations[0].InputDigest = testDigest
	if _, err := repository.GetStepBindings(context.Background(), changed, binding.OperationID); Code(err) != generated.ErrorCodeIntegrityFailure {
		t.Fatalf("tampered input accepted: %v", err)
	}
}

func openCredentialStore(t *testing.T) *CredentialRepository {
	t.Helper()
	authority, err := Open(context.Background(), testConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := authority.Close(); err != nil {
			t.Error(err)
		}
	})
	return NewCredentialRepository(authority)
}

func credentialBindingFixture() credentialref.StepBinding {
	return credentialref.StepBinding{OperationID: "operation-a", AdapterID: "adapter-a", TargetID: "service-a", ReferenceID: "ref-a", ConsumerID: "adapter-a", PurposeID: "deploy-a", MaterialVersion: "version-a", ResolverID: "native-a", StateRevision: 3, RecoveryEpoch: 0}
}

func planWithoutCredentialExtension() generated.Plan {
	digest := "sha256:" + strings.Repeat("a", 64)
	return generated.Plan{Schema: generated.SchemaIDPlan, SchemaVersion: "1.0.0", PlanID: "plan-a", PlanDigest: digest, DeclarationID: "declaration-a", Binding: generated.PlanBinding{StateRevision: 3, DeclarationRevision: 1, RecoveryEpoch: 0}, Operations: []generated.PlanOperation{{OperationID: "operation-a", AdapterID: "adapter-a", TargetID: "service-a", InputDigest: digest, ArtifactDigest: digest}}, Status: "planned", ExecutorMode: "central", Extensions: []generated.ContractExtension{}}
}

func TestDraftBindingCannotBecomeResolutionAuthority(t *testing.T) {
	repository := openCredentialStore(t)
	binding := credentialBindingFixture()
	if _, err := repository.GetStepBindings(context.Background(), planWithoutCredentialExtension(), binding.OperationID); Code(err) != generated.ErrorCodePrerequisiteBlocked {
		t.Fatalf("uncommitted binding read: %v", err)
	}
	for _, column := range credentialTableColumns(t, repository) {
		if column == "material" || column == "plaintext" || column == "secret" {
			t.Fatalf("secret column: %s", column)
		}
	}
}

func TestCredentialStatusCannotBypassHumanCentralPlanAndAppendOnlyLedger(t *testing.T) {
	repository := openCredentialStore(t)
	request := CredentialStageRequest{Reference: generated.CredentialReference{Schema: generated.SchemaIDCredentialReference, SchemaVersion: "1.1.0", ReferenceID: "ref-a", ConsumerID: "adapter-a", PurposeID: "deploy-a", TargetID: "service-a", ResolverID: "native-a", MaterialVersion: "version-a", Fingerprint: testDigest, Status: "staged", StateRevision: 1, RecoveryEpoch: 0, VerifiedConsumerIDs: []string{}}, DeclarationID: "declaration-a", DeclarationRevision: 1, PlanID: "plan-a", PlanDigest: testDigest, RunID: "run-a", StepID: "step-a", LeaseID: "lease-a", HumanID: "principal-test-1", Expected: RevisionToken{StateRevision: 0, RecoveryEpoch: 0}, Attribution: validDeclarationStoreRequest().Attribution, KeyDigest: testDigest, RequestDigest: testDigest}
	if _, err := repository.StageCredentialVersion(context.Background(), request); Code(err) != generated.ErrorCodePrerequisiteBlocked {
		t.Fatalf("staging bypassed exact plan: %v", err)
	}
	if _, err := repository.AppendCredentialStatus(context.Background(), CredentialStatusRequest{Stage: request, Status: "active"}); Code(err) != generated.ErrorCodePrerequisiteBlocked {
		t.Fatalf("activation bypassed exact plan: %v", err)
	}
	for _, table := range []string{"credential_reference_versions", "credential_step_bindings", "credential_resolution_records"} {
		var count int
		if err := repository.store.conn.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM sqlite_master WHERE type='trigger' AND tbl_name=?", table).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 2 {
			t.Fatalf("append-only triggers missing for %s: %d", table, count)
		}
	}
}

func credentialTableColumns(t *testing.T, repository *CredentialRepository) []string {
	t.Helper()
	var columns []string
	err := repository.store.Read(context.Background(), func(tx ReadTx) error {
		rows, err := tx.query(context.Background(), `PRAGMA table_info(credential_reference_versions)`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id int
			var name, kind string
			var notNull, primary int
			var defaultValue any
			if err := rows.Scan(&id, &name, &kind, &notNull, &defaultValue, &primary); err != nil {
				return err
			}
			columns = append(columns, name)
		}
		return rows.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	return columns
}
