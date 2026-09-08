package backup

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/store"
)

type recordingSource struct {
	mu                sync.Mutex
	inspection        store.SnapshotInspection
	backupBody        []byte
	backupErr         error
	inspectErr        error
	restoreErr        error
	onlineBackupCalls int
	inspectCalls      int
	restoreCalls      int
	policy            store.BackupStepPolicy
	restoreSource     string
	restoreTarget     string
	authorityPath     string
	authorityBytes    []byte
	restoredSentinel  string
}

func (source *recordingSource) OnlineBackup(_ context.Context, destination string, policy store.BackupStepPolicy) error {
	source.mu.Lock()
	defer source.mu.Unlock()
	source.onlineBackupCalls++
	source.policy = policy
	if source.backupErr != nil {
		return source.backupErr
	}
	body := source.backupBody
	if len(body) == 0 {
		body = []byte("synthetic sqlite snapshot")
	}
	return os.WriteFile(destination, body, 0o600)
}

func (source *recordingSource) InspectSnapshot(_ context.Context, _ string, _ store.SnapshotExpectation) (store.SnapshotInspection, error) {
	source.mu.Lock()
	defer source.mu.Unlock()
	source.inspectCalls++
	return source.inspection, source.inspectErr
}

func (source *recordingSource) RestoreSnapshot(_ context.Context, snapshot, target string) error {
	source.mu.Lock()
	defer source.mu.Unlock()
	source.restoreCalls++
	source.restoreSource = snapshot
	source.restoreTarget = target
	if source.restoreErr != nil {
		return source.restoreErr
	}
	body, err := os.ReadFile(snapshot)
	if err != nil {
		return err
	}
	if err := os.WriteFile(target, body, 0o600); err != nil {
		return err
	}
	source.restoredSentinel = string(body)
	return nil
}

type testArtifactLayout struct {
	root       string
	failAt     string
	published  map[string]publishedGeneration
	removeFail bool
}

func newTestArtifactLayout(t *testing.T) *testArtifactLayout {
	t.Helper()
	return &testArtifactLayout{root: t.TempDir(), published: make(map[string]publishedGeneration)}
}

func (layout *testArtifactLayout) BeginGeneration(_ context.Context, id string) (stagedGeneration, error) {
	if layout.failAt == "begin" {
		return stagedGeneration{}, errors.New("injected")
	}
	dir := filepath.Join(layout.root, ".staging-"+id)
	if err := os.Mkdir(dir, 0o700); err != nil {
		return stagedGeneration{}, err
	}
	return stagedGeneration{id: id, dir: dir, database: filepath.Join(dir, databaseFileName), manifest: filepath.Join(dir, manifestFileName)}, nil
}

func (layout *testArtifactLayout) SealDatabase(_ context.Context, staged stagedGeneration) (fileIdentity, int64, [32]byte, error) {
	if layout.failAt == "seal" {
		return fileIdentity{}, 0, [32]byte{}, errors.New("injected")
	}
	body, err := os.ReadFile(staged.database)
	if err != nil {
		return fileIdentity{}, 0, [32]byte{}, err
	}
	if len(body) == 0 {
		return fileIdentity{}, 0, [32]byte{}, errors.New("empty")
	}
	return fileIdentity{inode: 1, links: 1, mode: 0o600}, int64(len(body)), sha256.Sum256(body), nil
}

func (layout *testArtifactLayout) WriteManifest(_ context.Context, staged stagedGeneration, body []byte) error {
	if layout.failAt == "manifest" {
		return errors.New("injected")
	}
	return os.WriteFile(staged.manifest, body, 0o600)
}

func (layout *testArtifactLayout) Publish(_ context.Context, staged stagedGeneration) (publishedGeneration, error) {
	if layout.failAt == "publish" {
		return publishedGeneration{}, errors.New("injected")
	}
	if _, exists := layout.published[staged.id]; exists {
		return publishedGeneration{}, errors.New("collision")
	}
	dir := filepath.Join(layout.root, staged.id)
	if err := os.Rename(staged.dir, dir); err != nil {
		return publishedGeneration{}, err
	}
	published := publishedGeneration{id: staged.id, dir: dir, database: filepath.Join(dir, databaseFileName), manifest: filepath.Join(dir, manifestFileName), databaseIdentity: staged.databaseIdentity}
	layout.published[staged.id] = published
	return published, nil
}

func (layout *testArtifactLayout) OpenPublished(_ context.Context, id string) (publishedGeneration, []byte, error) {
	if layout.failAt == "open" {
		return publishedGeneration{}, nil, errors.New("injected")
	}
	published, ok := layout.published[id]
	if !ok {
		return publishedGeneration{}, nil, errors.New("missing")
	}
	body, err := os.ReadFile(published.manifest)
	return published, body, err
}

func (layout *testArtifactLayout) BeginRestore(_ context.Context, id string) (restoreTarget, error) {
	if layout.failAt == "begin-restore" {
		return restoreTarget{}, errors.New("injected")
	}
	dir := filepath.Join(layout.root, ".restore-"+id)
	if err := os.Mkdir(dir, 0o700); err != nil {
		return restoreTarget{}, err
	}
	return restoreTarget{dir: dir, database: filepath.Join(dir, databaseFileName)}, nil
}

func (layout *testArtifactLayout) SealRestore(_ context.Context, target restoreTarget) (fileIdentity, int64, error) {
	if layout.failAt == "seal-restore" {
		return fileIdentity{}, 0, errors.New("injected")
	}
	info, err := os.Stat(target.database)
	if err != nil {
		return fileIdentity{}, 0, err
	}
	return fileIdentity{inode: 2, links: 1, mode: 0o600}, info.Size(), nil
}

func (layout *testArtifactLayout) RemoveRestore(_ context.Context, target restoreTarget) error {
	if layout.removeFail {
		return errors.New("injected")
	}
	return os.RemoveAll(target.dir)
}

func newTestService(t *testing.T) (*Service, *testArtifactLayout) {
	t.Helper()
	layout := newTestArtifactLayout(t)
	clock := time.Date(2026, 9, 8, 10, 0, 0, 0, time.UTC)
	service := &Service{config: Config{Clock: func() time.Time { clock = clock.Add(time.Second); return clock }}, layout: layout, entropy: &sequenceEntropy{next: 1}}
	return service, layout
}

type sequenceEntropy struct {
	mu   sync.Mutex
	next byte
}

func (entropy *sequenceEntropy) Read(buffer []byte) (int, error) {
	entropy.mu.Lock()
	defer entropy.mu.Unlock()
	for index := range buffer {
		buffer[index] = entropy.next
	}
	entropy.next++
	return len(buffer), nil
}

func validMigrationRequestForTest(t *testing.T) store.MigrationRequest {
	t.Helper()
	return store.MigrationRequest{
		Purpose:              snapshotPurpose,
		ToolVersion:          "test-tool",
		BuildVersion:         "test-build",
		CurrentSchemaVersion: 1,
		TargetSchemaVersion:  2,
		CatalogSHA256:        sha256.Sum256([]byte("catalog")),
		CurrentRevision:      store.RevisionToken{StateRevision: 41, RecoveryEpoch: 2},
		BusyBudget:           25 * time.Millisecond,
		RequestedAt:          time.Date(2026, 9, 8, 9, 59, 0, 0, time.UTC),
	}
}
