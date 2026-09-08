package backup

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/store"
)

func TestVerifyRestorableUsesIsolatedTargetAndLeavesAuthorityUntouched(t *testing.T) {
	service, source, snapshot := preparedSnapshot(t)
	authorityBefore := append([]byte(nil), source.authorityBytes...)
	evidence, err := service.VerifyRestorable(context.Background(), source, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if evidence.Status != "verified" || evidence.SnapshotID != snapshot.SnapshotID || evidence.SchemaVersion != snapshot.SchemaVersion || evidence.Revision != snapshot.Revision {
		t.Fatalf("evidence = %#v", evidence)
	}
	if source.restoreSource == source.authorityPath || source.restoreTarget == source.authorityPath || source.restoreSource == source.restoreTarget {
		t.Fatalf("unsafe restore paths: source=%q target=%q", source.restoreSource, source.restoreTarget)
	}
	if !bytes.Equal(source.authorityBytes, authorityBefore) {
		t.Fatal("authority changed during restore verification")
	}
	if source.restoredSentinel != "before-migration" {
		t.Fatalf("sentinel = %q", source.restoredSentinel)
	}
	if _, err := os.Lstat(source.restoreTarget); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("isolated restore target was retained")
	}
}

func TestVerifyRestorableRejectsOpaqueRecordMismatchBeforeRestore(t *testing.T) {
	for name, mutate := range map[string]func(*store.VerifiedSnapshot){
		"id":       func(s *store.VerifiedSnapshot) { s.SnapshotID = "ffffffffffffffffffffffffffffffff" },
		"schema":   func(s *store.VerifiedSnapshot) { s.SchemaVersion++ },
		"revision": func(s *store.VerifiedSnapshot) { s.Revision.StateRevision++ },
		"epoch":    func(s *store.VerifiedSnapshot) { s.Revision.RecoveryEpoch++ },
		"catalog":  func(s *store.VerifiedSnapshot) { s.CatalogSHA256[0]++ },
	} {
		t.Run(name, func(t *testing.T) {
			service, source, snapshot := preparedSnapshot(t)
			mutate(&snapshot)
			evidence, err := service.VerifyRestorable(context.Background(), source, snapshot)
			if err == nil || evidence.Status != "failed" || source.restoreCalls != 0 {
				t.Fatalf("VerifyRestorable() = (%#v, %v), calls=%d", evidence, err, source.restoreCalls)
			}
		})
	}
}

func TestVerifyRestorableFailsClosedAndCleansIsolatedTarget(t *testing.T) {
	for _, stage := range []string{"open", "begin-restore", "restore", "seal-restore", "inspect"} {
		t.Run(stage, func(t *testing.T) {
			service, source, snapshot := preparedSnapshot(t)
			layout := service.layout.(*testArtifactLayout)
			switch stage {
			case "restore":
				source.restoreErr = errors.New("private restore path")
			case "inspect":
				source.inspectErr = errors.New("private row")
			default:
				layout.failAt = stage
			}
			evidence, err := service.VerifyRestorable(context.Background(), source, snapshot)
			if err == nil || evidence.Status != "failed" || evidence.FailureCode == "" || strings.Contains(err.Error(), "private") || strings.Contains(evidence.FailureCode, "/") {
				t.Fatalf("VerifyRestorable() = (%#v, %v)", evidence, err)
			}
			if source.restoreTarget != "" {
				if _, statErr := os.Lstat(source.restoreTarget); !errors.Is(statErr, os.ErrNotExist) {
					t.Fatalf("restore target remains: %v", statErr)
				}
			}
		})
	}
}

func TestVerifyRestorableReportsCleanupFailureWithoutSuccess(t *testing.T) {
	service, source, snapshot := preparedSnapshot(t)
	service.layout.(*testArtifactLayout).removeFail = true
	evidence, err := service.VerifyRestorable(context.Background(), source, snapshot)
	if err == nil || evidence.Status != "failed" || evidence.FailureCode != failureIntegrity {
		t.Fatalf("VerifyRestorable() = (%#v, %v)", evidence, err)
	}
}

func TestVerifyRestorableHonorsCancellation(t *testing.T) {
	service, source, snapshot := preparedSnapshot(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	evidence, err := service.VerifyRestorable(ctx, source, snapshot)
	if err == nil || err.Error() != failureInterrupted || evidence.Status != "failed" || evidence.FailureCode != failureInterrupted {
		t.Fatalf("VerifyRestorable() = (%#v, %v)", evidence, err)
	}
}

func preparedSnapshot(t *testing.T) (*Service, *recordingSource, store.VerifiedSnapshot) {
	t.Helper()
	service, _ := newTestService(t)
	source := &recordingSource{
		inspection:       validInspection(),
		backupBody:       []byte("before-migration"),
		authorityPath:    "/synthetic/authority.db",
		authorityBytes:   []byte("current-authority"),
		restoredSentinel: "before-migration",
	}
	snapshot, err := service.Prepare(context.Background(), source, validMigrationRequestForTest(t))
	if err != nil {
		t.Fatal(err)
	}
	return service, source, snapshot
}
