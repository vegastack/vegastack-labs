//go:build linux

package backup

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type retentionJournalFixture struct {
	mu        sync.Mutex
	beginErr  error
	finishErr error
	attempts  []RetainedMutationAttempt
	outcomes  []RetainedMutationOutcome
}

func (fixture *retentionJournalFixture) BeginRetainedMutation(_ context.Context, attempt RetainedMutationAttempt) error {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	fixture.attempts = append(fixture.attempts, attempt)
	return fixture.beginErr
}

func (fixture *retentionJournalFixture) FinishRetainedMutation(_ context.Context, outcome RetainedMutationOutcome) error {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	fixture.outcomes = append(fixture.outcomes, outcome)
	return fixture.finishErr
}

func TestRetainedMutationIDBindsLeaseAndSequence(t *testing.T) {
	first := retainedMutationID("lease-a", 1)
	if first == "" || first != retainedMutationID("lease-a", 1) || first == retainedMutationID("lease-a", 2) || first == retainedMutationID("lease-b", 1) {
		t.Fatal("retention mutation identity is not exact and replay-stable")
	}
}

func TestRetentionDeleteQuarantinesExactInodeAcrossJournalCrashes(t *testing.T) {
	var fs unix.Statfs_t
	if err := unix.Statfs(t.TempDir(), &fs); err != nil || fs.Type != unix.EXT4_SUPER_MAGIC {
		t.Skip("disposable ext-family filesystem required")
	}
	for _, test := range []struct {
		name      string
		beginErr  error
		finishErr error
		wantLive  bool
		wantHeld  bool
	}{
		{name: "crash-after-journal", beginErr: errors.New("injected journal interruption"), wantLive: true},
		{name: "crash-after-quarantine-rename", finishErr: errors.New("injected outcome interruption"), wantHeld: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			base := t.TempDir()
			if err := os.Chmod(base, 0o700); err != nil {
				t.Fatal(err)
			}
			root := filepath.Join(base, "repository")
			quarantine := filepath.Join(base, "quarantine")
			if err := os.Mkdir(root, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(filepath.Join(root, "data"), 0o700); err != nil {
				t.Fatal(err)
			}
			name := strings.Repeat("a", 64)
			original := filepath.Join(root, "data", name)
			if err := os.WriteFile(original, []byte("retained survivor pack"), 0o600); err != nil {
				t.Fatal(err)
			}
			before, err := os.Stat(original)
			if err != nil {
				t.Fatal(err)
			}
			journal := &retentionJournalFixture{beginErr: test.beginErr, finishErr: test.finishErr}
			lease := RetentionLease{LeaseID: "lease-test", RepositoryID: "repo-test", RecoveryEpoch: 3, MaximumExpiresAt: time.Now().Add(time.Minute), MaxMutations: 1, MaxMutationBytes: 1024}
			server, err := NewRetentionRESTServer(root, quarantine, uint32(os.Geteuid()), lease, allowingRetentionLeaseVerifier{}, journal, time.Now)
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodDelete, "/repo-test/data/"+name, nil)
			response := httptest.NewRecorder()
			server.ServeHTTP(response, request)
			if response.Code < 400 {
				t.Fatalf("injected crash returned success: %d", response.Code)
			}
			_, liveErr := os.Stat(original)
			if (liveErr == nil) != test.wantLive {
				t.Fatalf("visible pack live=%t want=%t", liveErr == nil, test.wantLive)
			}
			held := filepath.Join(quarantine, "data", name)
			heldInfo, heldErr := os.Stat(held)
			if (heldErr == nil) != test.wantHeld {
				t.Fatalf("held pack exists=%t want=%t", heldErr == nil, test.wantHeld)
			}
			if test.wantHeld && !os.SameFile(before, heldInfo) {
				t.Fatal("quarantine copied or replaced the old pack inode")
			}
			if len(journal.attempts) != 1 || journal.attempts[0].ObjectType != "data" || journal.attempts[0].ObjectName != name {
				t.Fatalf("journal attempts=%#v", journal.attempts)
			}
		})
	}
}

func TestRetentionPutStagesBeforeJournalAndNeverOverwrites(t *testing.T) {
	for _, test := range []struct {
		name      string
		beginErr  error
		finishErr error
		wantLive  bool
		wantStage bool
	}{
		{name: "journal-unavailable", beginErr: errors.New("injected journal interruption"), wantStage: true},
		{name: "outcome-lost", finishErr: errors.New("injected outcome interruption"), wantLive: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			base := t.TempDir()
			if err := os.Chmod(base, 0o700); err != nil {
				t.Fatal(err)
			}
			root := filepath.Join(base, "repository")
			if err := os.Mkdir(root, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(filepath.Join(root, "data"), 0o700); err != nil {
				t.Fatal(err)
			}
			quarantine := filepath.Join(base, "quarantine")
			journal := &retentionJournalFixture{beginErr: test.beginErr, finishErr: test.finishErr}
			lease := RetentionLease{LeaseID: "lease-test", RepositoryID: "repo-test", RecoveryEpoch: 3, MaximumExpiresAt: time.Now().Add(time.Minute), MaxMutations: 2, MaxMutationBytes: 1024}
			server, err := NewRetentionRESTServer(root, quarantine, uint32(os.Geteuid()), lease, allowingRetentionLeaseVerifier{}, journal, time.Now)
			if err != nil {
				t.Fatal(err)
			}
			name := strings.Repeat("b", 64)
			body := "replacement pack bytes"
			request := httptest.NewRequest(http.MethodPost, "/repo-test/data/"+name, strings.NewReader(body))
			response := httptest.NewRecorder()
			server.ServeHTTP(response, request)
			if response.Code < 400 {
				t.Fatalf("injected crash returned success: %d", response.Code)
			}
			live := filepath.Join(root, "data", name)
			staged := filepath.Join(quarantine, "staging", "data", name)
			_, liveErr := os.Stat(live)
			_, stageErr := os.Stat(staged)
			if (liveErr == nil) != test.wantLive || (stageErr == nil) != test.wantStage {
				t.Fatalf("live=%t staged=%t", liveErr == nil, stageErr == nil)
			}
			if len(journal.attempts) != 1 || journal.attempts[0].MutationKind != "put" || journal.attempts[0].Bytes != int64(len(body)) {
				t.Fatalf("attempt=%#v", journal.attempts)
			}
			if test.wantLive {
				if contents, err := os.ReadFile(live); err != nil || string(contents) != body {
					t.Fatalf("visible bytes=%q err=%v", contents, err)
				}
				again := httptest.NewRecorder()
				server.ServeHTTP(again, httptest.NewRequest(http.MethodPut, "/repo-test/data/"+name, strings.NewReader("different")))
				if again.Code < 400 {
					t.Fatal("retention role overwrote a retained pack")
				}
			}
		})
	}
}

type allowingRetentionLeaseVerifier struct{}

func (allowingRetentionLeaseVerifier) VerifyRetentionLease(RetentionLease, time.Time) error {
	return nil
}
