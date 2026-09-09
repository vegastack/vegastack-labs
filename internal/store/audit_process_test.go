//go:build linux

package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/audit"
)

const auditCrashExitCode = 73

func TestAuditCrashRestartNeverExposesPartialIntent(t *testing.T) {
	for _, stage := range []auditIntentStage{auditAfterBusiness, auditAfterEvent, auditAfterOutbox, auditBeforeCommit, auditAfterCommit} {
		t.Run(string(stage), func(t *testing.T) {
			path := runAuditCrashChild(t, stage)
			store := reopenAuditStore(t, path)
			defer store.Close()
			counts := readCrashLayerCounts(t, store)
			want := crashLayerCounts{}
			if stage == auditAfterCommit {
				want = crashLayerCounts{Business: 1, Events: 1, IntentKeys: 1, Outbox: 2}
			}
			if counts != want {
				t.Fatalf("partial durable state after %s: got %#v, want %#v", stage, counts, want)
			}
			assertEventSequenceConsistent(t, store)
		})
	}
}

func TestAuditCrashChild(t *testing.T) {
	if os.Getenv("VSK_AUDIT_CRASH_HELPER") != "1" {
		return
	}
	stage := auditIntentStage(os.Getenv("VSK_AUDIT_CRASH_STAGE"))
	path := os.Getenv("VSK_AUDIT_CRASH_DB")
	store, err := Open(context.Background(), auditProcessConfig(path, InitializeNew))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.conn.ExecContext(context.Background(), `CREATE TABLE audit_business(id TEXT PRIMARY KEY) STRICT`); err != nil {
		t.Fatal(err)
	}
	store.auditFault = func(got auditIntentStage) error {
		if got == stage {
			os.Exit(auditCrashExitCode)
		}
		return nil
	}
	_, err = store.writeIntent(context.Background(), publicIntentRequest(t, "a", twoDestinations()), insertSyntheticBusiness)
	if err != nil {
		t.Fatal(err)
	}
	t.Fatal("crash stage was not reached")
}

func TestAuditCanonicalPayloadAndRetryStateSurviveRestart(t *testing.T) {
	directory := secureTempDirectory(t)
	path := filepath.Join(directory, "control.db")
	store, err := Open(context.Background(), auditProcessConfig(path, InitializeNew))
	if err != nil {
		t.Fatal(err)
	}
	request := operationalAuditRequest("b", []audit.OutboxRequirement{{Destination: "audit-primary", Enabled: true}})
	result, err := store.AppendOperationalAudit(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	var originalPayload []byte
	var originalDigest string
	if err := store.conn.QueryRowContext(context.Background(), `SELECT canonical_payload,payload_sha256 FROM audit_events WHERE event_id=?`, result.EventID).Scan(&originalPayload, &originalDigest); err != nil {
		t.Fatal(err)
	}
	var outboxID audit.OutboxID
	if err := store.conn.QueryRowContext(context.Background(), `SELECT outbox_id FROM outbox WHERE event_id=?`, result.EventID).Scan(&outboxID); err != nil {
		t.Fatal(err)
	}
	attemptedAt := outboxAttemptTime(t, store, outboxID)
	failed, err := store.RecordOutboxAttempt(context.Background(), audit.OutboxAttempt{OutboxID: outboxID, ExpectedAttempt: 0, Retryable: true, ErrorCode: audit.DestinationUnavailable, AttemptedAt: attemptedAt})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened := reopenAuditStore(t, path)
	defer reopened.Close()
	record, err := reopened.InspectOutbox(context.Background(), outboxID)
	if err != nil || record.Status != audit.OutboxRetryWait || record.AttemptCount != 1 || record.NextAttemptAt == nil || !record.NextAttemptAt.Equal(*failed.NextAttemptAt) {
		t.Fatalf("reopened outbox = %#v, %v", record, err)
	}
	verifiedPayload, err := reopened.payloadForAttempt(context.Background(), outboxID, *record.NextAttemptAt)
	if err != nil || !bytes.Equal(verifiedPayload, originalPayload) {
		t.Fatalf("verified reopened payload = %d bytes, %v", len(verifiedPayload), err)
	}
	var event audit.Event
	if err := json.Unmarshal(originalPayload, &event); err != nil {
		t.Fatal(err)
	}
	canonical, digest, err := audit.CanonicalEvent(event)
	if err != nil || !bytes.Equal(canonical, originalPayload) || string(digest) != originalDigest {
		t.Fatalf("canonical reopen mismatch: %v", err)
	}
	assertEventSequenceConsistent(t, reopened)
}

func TestAuditArtifactsExcludeEveryPublicCanary(t *testing.T) {
	raw, err := os.ReadFile("../audit/testdata/public-canaries.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		ForbiddenValues []string `json:"forbiddenValues"`
		PEMHeaderParts  []string `json:"pemHeaderParts"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	fixture.ForbiddenValues = append(fixture.ForbiddenValues, strings.Join(fixture.PEMHeaderParts, ""))
	var diagnostics strings.Builder
	for index, canary := range fixture.ForbiddenValues {
		directory := secureTempDirectory(t)
		path := filepath.Join(directory, "control.db")
		store, openErr := Open(context.Background(), auditProcessConfig(path, InitializeNew))
		if openErr != nil {
			t.Fatal(openErr)
		}
		request := operationalAuditRequest("c", nil)
		request.Idempotency.KeyDigest = digestForText(fmt.Sprintf("canary-key-%d", index))
		request.Idempotency.RequestDigest = digestForText(fmt.Sprintf("canary-request-%d", index))
		request.Event.Type = audit.EventType(canary)
		_, appendErr := store.AppendOperationalAudit(context.Background(), request)
		if appendErr == nil {
			t.Fatal("unsafe event type accepted")
		}
		diagnostics.WriteString(appendErr.Error())
		accepted := operationalAuditRequest("d", []audit.OutboxRequirement{{Destination: "audit-primary", Enabled: true}})
		if _, acceptedErr := store.AppendOperationalAudit(context.Background(), accepted); acceptedErr != nil {
			t.Fatal(acceptedErr)
		}
		cancelledContext, cancel := context.WithCancel(context.Background())
		cancel()
		cancelled := operationalAuditRequest("e", nil)
		if _, cancelledErr := store.AppendOperationalAudit(cancelledContext, cancelled); Code(cancelledErr) != "INTERRUPTED" {
			t.Fatalf("cancelled append = %v", cancelledErr)
		} else {
			diagnostics.WriteString(cancelledErr.Error())
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		for _, artifact := range []string{path, path + "-journal"} {
			contents, readErr := os.ReadFile(artifact)
			if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
				t.Fatal(readErr)
			}
			for _, forbidden := range fixture.ForbiddenValues {
				if bytes.Contains(contents, []byte(forbidden)) {
					t.Fatalf("public canary persisted in %s", filepath.Base(artifact))
				}
			}
		}
	}
	hostile := ""
	for _, canary := range fixture.ForbiddenValues {
		if strings.Contains(canary, "hostile") {
			hostile = canary
		}
	}
	if hostile == "" {
		t.Fatal("hostile public error canary is missing")
	}
	directory := secureTempDirectory(t)
	path := filepath.Join(directory, "control.db")
	store, err := Open(context.Background(), auditProcessConfig(path, InitializeNew))
	if err != nil {
		t.Fatal(err)
	}
	store.auditFault = func(stage auditIntentStage) error {
		if stage == auditAfterEvent {
			return errors.New(hostile)
		}
		return nil
	}
	_, faultErr := store.AppendOperationalAudit(context.Background(), operationalAuditRequest("f", nil))
	if Code(faultErr) != "INTEGRITY_FAILURE" || strings.Contains(faultErr.Error(), hostile) {
		t.Fatalf("hostile internal error = %v", faultErr)
	}
	diagnostics.WriteString(faultErr.Error())
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	for _, artifact := range []string{path, path + "-journal"} {
		contents, readErr := os.ReadFile(artifact)
		if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
			t.Fatal(readErr)
		}
		for _, forbidden := range fixture.ForbiddenValues {
			if bytes.Contains(contents, []byte(forbidden)) {
				t.Fatalf("public canary persisted in %s", filepath.Base(artifact))
			}
		}
	}
	for _, canary := range fixture.ForbiddenValues {
		if strings.Contains(diagnostics.String(), canary) {
			t.Fatal("public canary leaked through diagnostics")
		}
	}
}

func runAuditCrashChild(t *testing.T, stage auditIntentStage) string {
	t.Helper()
	directory := secureTempDirectory(t)
	path := filepath.Join(directory, "control.db")
	command := exec.Command(os.Args[0], "-test.run=^TestAuditCrashChild$", "-test.v")
	command.Env = append(os.Environ(), "VSK_AUDIT_CRASH_HELPER=1", "VSK_AUDIT_CRASH_STAGE="+string(stage), "VSK_AUDIT_CRASH_DB="+path)
	output, err := command.CombinedOutput()
	var exitError *exec.ExitError
	if !errors.As(err, &exitError) || exitError.ExitCode() != auditCrashExitCode {
		t.Fatalf("crash helper %s = %v\n%s", stage, err, output)
	}
	return path
}

func secureTempDirectory(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return directory
}

func auditProcessConfig(path string, mode OpenMode) Config {
	return Config{DatabasePath: path, Mode: mode, BusyTimeout: 250 * time.Millisecond, ExpectedUID: uint32(os.Geteuid()), ToolVersion: "audit-process-test", BuildVersion: "audit-process-test"}
}

func reopenAuditStore(t *testing.T, path string) *Store {
	t.Helper()
	store, err := Open(context.Background(), auditProcessConfig(path, OpenExisting))
	if err != nil {
		t.Fatal(err)
	}
	return store
}

type crashLayerCounts struct {
	Business   int
	Events     int
	IntentKeys int
	Outbox     int
}

func readCrashLayerCounts(t *testing.T, store *Store) crashLayerCounts {
	t.Helper()
	var counts crashLayerCounts
	for _, query := range []struct {
		SQL  string
		Dest *int
	}{
		{`SELECT count(*) FROM audit_business`, &counts.Business},
		{`SELECT count(*) FROM audit_events`, &counts.Events},
		{`SELECT count(*) FROM intent_keys`, &counts.IntentKeys},
		{`SELECT count(*) FROM outbox`, &counts.Outbox},
	} {
		if err := store.conn.QueryRowContext(context.Background(), query.SQL).Scan(query.Dest); err != nil {
			t.Fatal(err)
		}
	}
	return counts
}

func assertEventSequenceConsistent(t *testing.T, store *Store) {
	t.Helper()
	var count, sequence int64
	var minimum, maximum sql.NullInt64
	if err := store.conn.QueryRowContext(context.Background(), `SELECT count(*),min(event_id),max(event_id) FROM audit_events`).Scan(&count, &minimum, &maximum); err != nil {
		t.Fatal(err)
	}
	if err := store.conn.QueryRowContext(context.Background(), `SELECT audit_sequence FROM system_meta WHERE id=1`).Scan(&sequence); err != nil {
		t.Fatal(err)
	}
	if count == 0 {
		if sequence != 0 || minimum.Valid || maximum.Valid {
			t.Fatalf("empty sequence = count %d, sequence %d, min/max %v/%v", count, sequence, minimum, maximum)
		}
		return
	}
	if minimum.Int64 != 1 || maximum.Int64 != count || sequence != count {
		t.Fatalf("sequence = count %d, sequence %d, min/max %d/%d", count, sequence, minimum.Int64, maximum.Int64)
	}
}

func digestForText(value string) audit.Fingerprint {
	digest := sha256.Sum256([]byte(value))
	return audit.Fingerprint("sha256:" + hex.EncodeToString(digest[:]))
}
