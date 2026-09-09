package backup

import (
	"bytes"
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/store"
)

func TestPreparePublishesOnlyTheInspectedCompletedBackup(t *testing.T) {
	source := &recordingSource{inspection: store.SnapshotInspection{
		SQLiteVersion: "3.53.4", SchemaVersion: 1,
		Revision:        store.RevisionToken{StateRevision: 41, RecoveryEpoch: 2},
		IntegrityStatus: store.IntegrityVerified,
	}}
	service, _ := newTestService(t)
	request := validMigrationRequestForTest(t)
	got, err := service.Prepare(context.Background(), source, request)
	if err != nil {
		t.Fatal(err)
	}
	if source.onlineBackupCalls != 1 || source.inspectCalls != 1 {
		t.Fatalf("calls = %d/%d", source.onlineBackupCalls, source.inspectCalls)
	}
	if source.policy != (store.BackupStepPolicy{PagesPerStep: 128, BusyBudget: request.BusyBudget}) {
		t.Fatalf("policy = %#v", source.policy)
	}
	if got.SchemaVersion != source.inspection.SchemaVersion || got.Revision != source.inspection.Revision || got.CatalogSHA256 != request.CatalogSHA256 {
		t.Fatalf("snapshot = %#v", got)
	}
	manifest := openManifestForTest(t, service, got.SnapshotID)
	if manifest.StateRevision != 41 || manifest.RecoveryEpoch != 2 || manifest.Verification != VerificationPassed {
		t.Fatalf("manifest = %#v", manifest)
	}
}

func TestPrepareFailsClosedForEveryIncompleteStage(t *testing.T) {
	for _, stage := range []string{"begin", "backup", "seal", "inspect", "manifest", "publish"} {
		t.Run(stage, func(t *testing.T) {
			service, layout := newTestService(t)
			source := &recordingSource{inspection: validInspection()}
			switch stage {
			case "backup":
				source.backupErr = errors.New("private disk full path")
			case "inspect":
				source.inspectErr = errors.New("private corrupt row")
			default:
				layout.failAt = stage
			}
			if got, err := service.Prepare(context.Background(), source, validMigrationRequestForTest(t)); err == nil || got.SnapshotID != "" || err.Error() == "private disk full path" {
				t.Fatalf("Prepare() = (%#v, %v)", got, err)
			}
			if len(layout.published) != 0 {
				t.Fatal("incomplete generation published")
			}
		})
	}
}

func TestPrepareRejectsMismatchedInspectionAndCancellation(t *testing.T) {
	cases := map[string]func(*recordingSource){
		"schema":    func(s *recordingSource) { s.inspection.SchemaVersion++ },
		"revision":  func(s *recordingSource) { s.inspection.Revision.StateRevision++ },
		"epoch":     func(s *recordingSource) { s.inspection.Revision.RecoveryEpoch++ },
		"integrity": func(s *recordingSource) { s.inspection.IntegrityStatus = store.IntegrityFailed },
		"sqlite":    func(s *recordingSource) { s.inspection.SQLiteVersion = "" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			service, layout := newTestService(t)
			source := &recordingSource{inspection: validInspection()}
			mutate(source)
			if _, err := service.Prepare(context.Background(), source, validMigrationRequestForTest(t)); err == nil || len(layout.published) != 0 {
				t.Fatalf("Prepare() error = %v", err)
			}
		})
	}

	service, _ := newTestService(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := service.Prepare(ctx, &recordingSource{inspection: validInspection()}, validMigrationRequestForTest(t)); err == nil || err.Error() != failureInterrupted {
		t.Fatalf("cancel error = %v", err)
	}
}

func TestConcurrentPrepareUsesDistinctGenerationIDs(t *testing.T) {
	service, layout := newTestService(t)
	const count = 8
	var wait sync.WaitGroup
	wait.Add(count)
	errorsFound := make(chan error, count)
	for index := 0; index < count; index++ {
		go func() {
			defer wait.Done()
			_, err := service.Prepare(context.Background(), &recordingSource{inspection: validInspection()}, validMigrationRequestForTest(t))
			errorsFound <- err
		}()
	}
	wait.Wait()
	close(errorsFound)
	for err := range errorsFound {
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(layout.published) != count {
		t.Fatalf("published = %d", len(layout.published))
	}
}

func TestPrepareRejectsInvalidRequestsAndEntropyFailure(t *testing.T) {
	base := validMigrationRequestForTest(t)
	cases := map[string]func(*store.MigrationRequest){
		"purpose":       func(r *store.MigrationRequest) { r.Purpose = "scheduled" },
		"tool":          func(r *store.MigrationRequest) { r.ToolVersion = "" },
		"build":         func(r *store.MigrationRequest) { r.BuildVersion = "" },
		"currentSchema": func(r *store.MigrationRequest) { r.CurrentSchemaVersion = 0 },
		"targetSchema":  func(r *store.MigrationRequest) { r.TargetSchemaVersion = r.CurrentSchemaVersion },
		"catalog":       func(r *store.MigrationRequest) { r.CatalogSHA256 = [32]byte{} },
		"revision":      func(r *store.MigrationRequest) { r.CurrentRevision.StateRevision = -1 },
		"epoch":         func(r *store.MigrationRequest) { r.CurrentRevision.RecoveryEpoch = -1 },
		"budget":        func(r *store.MigrationRequest) { r.BusyBudget = 0 },
		"requested":     func(r *store.MigrationRequest) { r.RequestedAt = time.Time{} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			request := base
			mutate(&request)
			service, _ := newTestService(t)
			if _, err := service.Prepare(context.Background(), &recordingSource{inspection: validInspection()}, request); err == nil {
				t.Fatal("invalid request accepted")
			}
		})
	}
	service, _ := newTestService(t)
	service.entropy = errorReader{}
	if _, err := service.Prepare(context.Background(), &recordingSource{inspection: validInspection()}, base); err == nil || err.Error() != failureMigration {
		t.Fatalf("entropy error = %v", err)
	}
}

func TestPrepareCollisionPreservesEarlierPublishedGeneration(t *testing.T) {
	service, layout := newTestService(t)
	service.entropy = bytes.NewReader(bytes.Repeat([]byte{0x42}, snapshotIDByteLength*2))
	first, err := service.Prepare(context.Background(), &recordingSource{inspection: validInspection(), backupBody: []byte("first immutable snapshot")}, validMigrationRequestForTest(t))
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(layout.published[first.SnapshotID].database)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Prepare(context.Background(), &recordingSource{inspection: validInspection(), backupBody: []byte("replacement")}, validMigrationRequestForTest(t)); err == nil {
		t.Fatal("snapshot ID collision succeeded")
	}
	after, err := os.ReadFile(layout.published[first.SnapshotID].database)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("earlier published generation changed")
	}
}

func TestPrepareRootSyncFailureReturnsNoSuccessButLeavesValidGeneration(t *testing.T) {
	service, layout := newTestService(t)
	layout.failAt = "root-sync"
	got, err := service.Prepare(context.Background(), &recordingSource{inspection: validInspection()}, validMigrationRequestForTest(t))
	if err == nil || got.SnapshotID != "" || len(layout.published) != 1 {
		t.Fatalf("Prepare() = (%#v, %v), published=%d", got, err, len(layout.published))
	}
	for id := range layout.published {
		if _, _, openErr := layout.OpenPublished(context.Background(), id); openErr != nil {
			t.Fatalf("post-rename generation rejected: %v", openErr)
		}
	}
}

func TestPrepareFailuresNeverChangeEarlierGeneration(t *testing.T) {
	for _, stage := range []string{"begin", "backup", "seal", "inspect", "manifest", "publish", "root-sync"} {
		t.Run(stage, func(t *testing.T) {
			service, layout := newTestService(t)
			first, err := service.Prepare(context.Background(), &recordingSource{inspection: validInspection(), backupBody: []byte("earlier generation")}, validMigrationRequestForTest(t))
			if err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(layout.published[first.SnapshotID].database)
			if err != nil {
				t.Fatal(err)
			}
			source := &recordingSource{inspection: validInspection(), backupBody: []byte("later generation")}
			switch stage {
			case "backup":
				source.backupErr = errors.New("injected")
			case "inspect":
				source.inspectErr = errors.New("injected")
			default:
				layout.failAt = stage
			}
			if _, err := service.Prepare(context.Background(), source, validMigrationRequestForTest(t)); err == nil {
				t.Fatal("injected failure succeeded")
			}
			after, err := os.ReadFile(layout.published[first.SnapshotID].database)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Fatal("earlier generation changed")
			}
		})
	}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errors.New("injected entropy failure") }

func openManifestForTest(t *testing.T, service *Service, id string) Manifest {
	t.Helper()
	_, body, err := service.layout.OpenPublished(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := parseManifest(body)
	if err != nil {
		t.Fatal(err)
	}
	return manifest
}

func validInspection() store.SnapshotInspection {
	return store.SnapshotInspection{
		SQLiteVersion:   "3.53.4",
		SchemaVersion:   1,
		Revision:        store.RevisionToken{StateRevision: 41, RecoveryEpoch: 2},
		IntegrityStatus: store.IntegrityVerified,
	}
}
