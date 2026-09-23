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
	beginHook func()
	attempts  []RetainedMutationAttempt
	outcomes  []RetainedMutationOutcome
}

func (fixture *retentionJournalFixture) BeginRetainedMutation(_ context.Context, attempt RetainedMutationAttempt) error {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	fixture.attempts = append(fixture.attempts, attempt)
	if fixture.beginHook != nil {
		fixture.beginHook()
	}
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

func TestRetentionDeleteRejectsObjectSwappedAfterHash(t *testing.T) {
	var fs unix.Statfs_t
	if err := unix.Statfs(t.TempDir(), &fs); err != nil || fs.Type != unix.EXT4_SUPER_MAGIC {
		t.Skip("disposable ext-family filesystem required")
	}
	base := t.TempDir()
	if err := os.Chmod(base, 0o700); err != nil {
		t.Fatal(err)
	}
	root, quarantine := filepath.Join(base, "repository"), filepath.Join(base, "quarantine")
	if err := os.MkdirAll(filepath.Join(root, "data"), 0o700); err != nil {
		t.Fatal(err)
	}
	name := strings.Repeat("c", 64)
	visible := filepath.Join(root, "data", name)
	if err := os.WriteFile(visible, []byte("original pack"), 0o600); err != nil {
		t.Fatal(err)
	}
	j := &retentionJournalFixture{beginHook: func() {
		if err := os.Rename(visible, filepath.Join(base, "swapped-original")); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(visible, []byte("forged pack!!"), 0o600); err != nil {
			t.Fatal(err)
		}
	}}
	lease := RetentionLease{LeaseID: "lease-test", RepositoryID: "repo-test", RecoveryEpoch: 3, MaximumExpiresAt: time.Now().Add(time.Minute), MaxMutations: 1, MaxMutationBytes: 1024}
	server, err := NewRetentionRESTServer(root, quarantine, uint32(os.Geteuid()), lease, allowingRetentionLeaseVerifier{}, j, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	server.ServeHTTP(response, httptest.NewRequest(http.MethodDelete, "/repo-test/data/"+name, nil))
	if response.Code < 400 {
		t.Fatalf("swapped object was quarantined: %d", response.Code)
	}
	if _, err := os.Stat(visible); err != nil {
		t.Fatalf("replacement disappeared: %v", err)
	}
	if _, err := os.Stat(filepath.Join(quarantine, "data", name)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("swapped object entered quarantine: %v", err)
	}
	if len(j.attempts) != 1 || len(j.outcomes) != 1 || j.outcomes[0].Status != "uncertain" {
		t.Fatalf("swapped effect was reported complete: attempts=%d outcomes=%d", len(j.attempts), len(j.outcomes))
	}
}

// A last-moment pathname stat is only a detection step. Linux renameat2 has
// no expected-inode argument, so a same-UID writer that can edit this owner-
// only directory can replace the object after stat and before the rename.
// Keep the production retirement claim disabled until custody excludes that
// writer for the entire hash/journal/quarantine interval.
func TestRetentionPostStatRenameHasNoInodeCompareAndSwap(t *testing.T) {
	var fs unix.Statfs_t
	if err := unix.Statfs(t.TempDir(), &fs); err != nil || fs.Type != unix.EXT4_SUPER_MAGIC {
		t.Skip("disposable ext-family filesystem required")
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	source, held := filepath.Join(directory, "source"), filepath.Join(directory, "held")
	if err := os.Mkdir(source, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(held, 0o700); err != nil {
		t.Fatal(err)
	}
	name := strings.Repeat("d", 64)
	original := filepath.Join(source, name)
	if err := os.WriteFile(original, []byte("original pack"), 0o600); err != nil {
		t.Fatal(err)
	}
	sourceFD, err := unix.Open(source, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(sourceFD)
	heldFD, err := unix.Open(held, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(heldFD)
	var checked unix.Stat_t
	if err := unix.Fstatat(sourceFD, name, &checked, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(original, filepath.Join(directory, "saved-original")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(original, []byte("replacement!!"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := unix.Renameat2(sourceFD, name, heldFD, name, unix.RENAME_NOREPLACE); err != nil {
		t.Fatal(err)
	}
	var moved unix.Stat_t
	if err := unix.Fstatat(heldFD, name, &moved, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		t.Fatal(err)
	}
	if moved.Ino == checked.Ino || moved.Dev != checked.Dev {
		t.Fatal("test did not replace the exact checked inode before rename")
	}
	contents, err := os.ReadFile(filepath.Join(held, name))
	if err != nil || string(contents) != "replacement!!" {
		t.Fatalf("unexpected renamed bytes %q: %v", contents, err)
	}
}

func TestCustodyRetentionUsesExactPolicyQuarantine(t *testing.T) {
	base := t.TempDir()
	if err := os.Chmod(base, 0o700); err != nil {
		t.Fatal(err)
	}
	root, quarantine := filepath.Join(base, "repository"), filepath.Join(base, "fixed-quarantine")
	for _, path := range []string{root, quarantine} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC()
	lease := RetentionLease{LeaseID: "retention-policy-q", RepositoryID: "repository-a", RecoveryEpoch: 1, MaximumExpiresAt: now.Add(time.Minute), MaxMutations: 10, MaxMutationBytes: 1 << 20, PlannedSnapshotIDs: []string{strings.Repeat("a", 64)}}
	session := CustodySession{Role: "retention", RetentionLease: &lease}
	server, err := newCustodyRESTServer(root, quarantine, uint32(os.Geteuid()), uint32(os.Geteuid()), session, nil, nil, allowingRetentionLeaseVerifier{}, &retentionJournalFixture{}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if server.quarantineRoot != quarantine {
		t.Fatalf("quarantine=%q want policy path %q", server.quarantineRoot, quarantine)
	}
	if _, err := os.Stat(root + ".retirement-quarantine"); !os.IsNotExist(err) {
		t.Fatalf("synthesized quarantine exists: %v", err)
	}
}

func TestRetentionEarlyDenialIsJournaled(t *testing.T) {
	base := t.TempDir()
	if err := os.Chmod(base, 0o700); err != nil {
		t.Fatal(err)
	}
	root, quarantine := filepath.Join(base, "repository"), filepath.Join(base, "quarantine")
	for _, path := range []string{root, quarantine} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	journal := &retentionJournalFixture{}
	lease := RetentionLease{LeaseID: "retention-denial", RepositoryID: "repository-a", RecoveryEpoch: 2, MaximumExpiresAt: time.Now().Add(time.Minute), MaxMutations: 4, MaxMutationBytes: 1024, PlannedSnapshotIDs: []string{strings.Repeat("a", 64)}}
	server, err := NewRetentionRESTServer(root, quarantine, uint32(os.Geteuid()), lease, allowingRetentionLeaseVerifier{}, journal, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodDelete, "/repository-a/config", nil)
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status=%d", response.Code)
	}
	if len(journal.attempts) != 1 || journal.attempts[0].ObjectType != "config" || journal.attempts[0].MutationKind != "delete" {
		t.Fatalf("attempts=%+v", journal.attempts)
	}
	if len(journal.outcomes) != 1 || journal.outcomes[0].Status != "denied" {
		t.Fatalf("outcomes=%+v", journal.outcomes)
	}
}

type allowingRetentionLeaseVerifier struct{}

func (allowingRetentionLeaseVerifier) VerifyRetentionLease(RetentionLease, time.Time) error {
	return nil
}
