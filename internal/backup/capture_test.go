package backup

import (
	"context"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type recordingHook struct {
	began    bool
	finished bool
	success  bool
	beginErr error
}

func (hook *recordingHook) Begin(context.Context, PolicySource) (ConsistencyToken, error) {
	hook.began = true
	if hook.beginErr != nil {
		return ConsistencyToken{}, hook.beginErr
	}
	return ConsistencyToken{HookID: "sqlite-online", Value: "token"}, nil
}

func (hook *recordingHook) Finish(_ context.Context, _ ConsistencyToken, success bool) error {
	hook.finished = true
	hook.success = success
	return nil
}

type fakeOnlineSource struct {
	result        store.OnlineSnapshotResult
	err           error
	calls         int
	rawFileOpened bool
}

func (source *fakeOnlineSource) OnlineSnapshot(_ context.Context, _ store.OnlineSnapshotRequest) (store.OnlineSnapshotResult, error) {
	source.calls++
	return source.result, source.err
}

func validPolicySource() PolicySource {
	return PolicySource{
		Policy:         generated.BackupPolicy{ConsistencyHookID: "sqlite-online"},
		PolicyDigest:   "sha256:" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		SourceRevision: 3,
		RecoveryEpoch:  0,
		Expectation:    store.SnapshotExpectation{SchemaVersion: 15, Revision: store.RevisionToken{StateRevision: 3, RecoveryEpoch: 0}},
	}
}

func registryWith(id string, hook ConsistencyHook) *HookRegistry {
	registry := NewHookRegistry()
	_ = registry.Register(id, hook)
	return registry
}

func codeOf(err error) string {
	if stable, ok := failure.As(err); ok {
		return stable.Code
	}
	return store.Code(err)
}

func TestCaptureUsesSnapshotPortAndFinishesHookSuccessfully(t *testing.T) {
	source := &fakeOnlineSource{result: store.OnlineSnapshotResult{SchemaVersion: 15, Revision: store.RevisionToken{StateRevision: 3, RecoveryEpoch: 0}, Bytes: 4096}}
	hook := &recordingHook{}
	got, err := Capture(context.Background(), validPolicySource(), source, registryWith("sqlite-online", hook), t.TempDir()+"/snapshot.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	if source.rawFileOpened || source.calls != 1 || !hook.began || !hook.finished || !hook.success {
		t.Fatalf("source=%#v hook=%#v", source, hook)
	}
	if got.Consistency.HookID != "sqlite-online" || !got.Consistency.Success || got.Snapshot.Bytes != 4096 {
		t.Fatalf("result = %#v", got)
	}
}

func TestCaptureFailureFinishesHookUnsuccessfullyAndPublishesNothing(t *testing.T) {
	source := &fakeOnlineSource{err: failure.New(generated.ErrorCodeIntegrityFailure, "catalog", false)}
	hook := &recordingHook{}
	got, err := Capture(context.Background(), validPolicySource(), source, registryWith("sqlite-online", hook), t.TempDir()+"/snapshot.sqlite")
	if codeOf(err) != generated.ErrorCodeIntegrityFailure {
		t.Fatalf("err code = %q", codeOf(err))
	}
	if !hook.finished || hook.success {
		t.Fatalf("hook must finish unsuccessfully: %#v", hook)
	}
	if got.Consistency.Success || got.Snapshot.Bytes != 0 {
		t.Fatalf("failure published a point: %#v", got)
	}
}

func TestCaptureRejectsUnregisteredHookBeforeBegin(t *testing.T) {
	source := validPolicySource()
	source.Policy.ConsistencyHookID = "unregistered"
	fake := &fakeOnlineSource{}
	if _, err := Capture(context.Background(), source, fake, NewHookRegistry(), t.TempDir()+"/s.sqlite"); codeOf(err) != generated.ErrorCodePrerequisiteBlocked {
		t.Fatalf("err code = %q", codeOf(err))
	}
	if fake.calls != 0 {
		t.Fatal("snapshot attempted with an unregistered hook")
	}
}

func TestHookRegistryRejectsDuplicateAndResolvesRegistered(t *testing.T) {
	registry := NewHookRegistry()
	hook := &recordingHook{}
	if err := registry.Register("sqlite-online", hook); err != nil {
		t.Fatal(err)
	}
	if err := registry.Register("sqlite-online", hook); codeOf(err) != generated.ErrorCodeStateConflict {
		t.Fatalf("duplicate registration code = %q", codeOf(err))
	}
	if _, ok := registry.Resolve("sqlite-online"); !ok {
		t.Fatal("registered hook did not resolve")
	}
	if _, ok := registry.Resolve("absent"); ok {
		t.Fatal("unregistered hook resolved")
	}
}

func TestSQLiteOnlineHookRoundTripsAndCaptures(t *testing.T) {
	registry := DefaultHookRegistry()
	if _, ok := registry.Resolve(SQLiteOnlineHookID); !ok {
		t.Fatal("default registry lacks the sqlite-online hook")
	}
	source := &fakeOnlineSource{result: store.OnlineSnapshotResult{SchemaVersion: 15, Bytes: 8192}}
	got, err := Capture(context.Background(), validPolicySource(), source, registry, t.TempDir()+"/snap.sqlite")
	if err != nil || got.Consistency.HookID != SQLiteOnlineHookID || !got.Consistency.Success {
		t.Fatalf("capture with default hook = %#v, %v", got, err)
	}
}
