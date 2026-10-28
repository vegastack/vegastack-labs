package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/operations"
	"github.com/vegastack/vegastack-labs/internal/readmodel"
	"testing"
	"time"
)

func TestOperationsAtomicDedupePersistenceRecoveryAndOutage(t *testing.T) {
	s := portableDiscoveryStore(t)
	ctx := context.Background()
	actor := audit.Attribution{AuthenticatedPrincipalID: "operator-a", AuthenticatedPrincipalMethod: "local-os-peer"}
	now := s.config.Clock().UTC().Add(-time.Minute)
	o := operations.Observation{TargetDigest: operations.Digest("private-target"), Class: "source-health", State: readmodel.SourceFailed, Severity: "critical", ObservedAt: now}
	a, e := s.RecordOperationsObservation(ctx, RevisionToken{}, o, actor, "alerts-github")
	if e != nil || a.Status != "open" {
		t.Fatal(a, e)
	}
	a, e = s.RecordOperationsObservation(ctx, RevisionToken{}, o, actor, "alerts-github")
	if e != nil || a.Occurrences != 1 {
		t.Fatal("duplicate observation", a, e)
	}
	o.ObservedAt = now.Add(time.Second)
	if _, e = s.RecordOperationsObservation(ctx, RevisionToken{}, o, actor, "alerts-github"); e != nil {
		t.Fatal(e)
	}
	// Read through a fresh repository value sharing persisted SQLite, not evaluator memory.
	var databaseName, filename string
	var seq int
	if e = s.conn.QueryRowContext(ctx, `PRAGMA database_list`).Scan(&seq, &databaseName, &filename); e != nil {
		t.Fatal(e)
	}
	s.conn.Close()
	s.db.Close()
	db, e := sql.Open(sqliteDriverName, sqliteURI(filename))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { db.Close() })
	conn, e := db.Conn(ctx)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { conn.Close() })
	reopened := &Store{db: db, conn: conn, config: s.config, filesystem: s.filesystem, events: s.events, health: s.health}
	s = reopened
	alerts, e := reopened.OperationsAlerts(ctx, RevisionToken{})
	if e != nil || len(alerts) != 1 || alerts[0].Occurrences != 2 {
		t.Fatal(alerts, e)
	}
	due, e := s.DueOperationsDeliveries(ctx, "alerts-github", 0, s.config.Clock().UTC())
	if e != nil || len(due) != 1 {
		t.Fatal(due, e)
	}
	r, e := s.RecordOutboxAttempt(ctx, audit.OutboxAttempt{OutboxID: due[0].Record.OutboxID, ExpectedAttempt: 0, AttemptedAt: s.config.Clock().UTC(), Retryable: true, ErrorCode: audit.DestinationUnavailable})
	if e != nil || r.Status != audit.OutboxRetryWait {
		t.Fatal(r, e)
	}
	alerts, _ = s.OperationsAlerts(ctx, RevisionToken{})
	if alerts[0].Status != "open" {
		t.Fatal("outage changed truth")
	}
	o.State = readmodel.SourceStale
	o.ObservedAt = now.Add(2 * time.Second)
	s.RecordOperationsObservation(ctx, RevisionToken{}, o, actor, "alerts-github")
	o.State = readmodel.SourceHealthy
	o.Verified = true
	o.SampleAt = now.Add(3 * time.Second)
	o.ObservedAt = now.Add(3 * time.Second)
	a, e = s.RecordOperationsObservation(ctx, RevisionToken{}, o, actor, "alerts-github")
	if e != nil || a.Status != "closed" {
		t.Fatal(a, e)
	}
	due, e = s.DueOperationsDeliveries(ctx, "alerts-github", 0, s.config.Clock().UTC())
	if e != nil || len(due) != 0 {
		t.Fatal("recovery overtook retrying open", due, e)
	}
	if _, e = s.RecordOutboxAttempt(ctx, audit.OutboxAttempt{OutboxID: r.OutboxID, ExpectedAttempt: 1, AttemptedAt: *r.NextAttemptAt, Delivered: true}); e != nil {
		t.Fatal(e)
	}
	due, e = s.DueOperationsDeliveries(ctx, "alerts-github", 0, *r.NextAttemptAt)
	if e != nil || len(due) != 1 || due[0].Event.Type != "operations.alert.closed" {
		t.Fatal(due, e)
	}
	raw, _ := json.Marshal(due)
	if containsString(string(raw), "private-target") {
		t.Fatal("raw target leaked")
	}
	if _, e = s.DueOperationsDeliveries(ctx, "alerts-github", 1, s.config.Clock().UTC()); Code(e) != "RECOVERY_EPOCH_MISMATCH" {
		t.Fatal(e)
	}
}
func containsString(s, v string) bool {
	for i := 0; i+len(v) <= len(s); i++ {
		if s[i:i+len(v)] == v {
			return true
		}
	}
	return false
}
func TestOperationsInvalidAttributionRollsBackObservation(t *testing.T) {
	s := portableDiscoveryStore(t)
	o := operations.Observation{TargetDigest: operations.Digest("target"), Class: "source-health", State: readmodel.SourceFailed, Severity: "critical", ObservedAt: s.config.Clock().UTC()}
	if _, e := s.RecordOperationsObservation(context.Background(), RevisionToken{}, o, audit.Attribution{}, ""); e == nil {
		t.Fatal("bad actor accepted")
	}
	a, e := s.OperationsAlerts(context.Background(), RevisionToken{})
	if e != nil || len(a) != 0 {
		t.Fatal(a, e)
	}
}

func TestOperationsOutboxBoundedDeadLetterAndIntegrity(t *testing.T) {
	s := portableDiscoveryStore(t)
	ctx := context.Background()
	now := s.config.Clock().UTC()
	actor := audit.Attribution{AuthenticatedPrincipalID: "operator-a", AuthenticatedPrincipalMethod: "local-os-peer"}
	o := operations.Observation{TargetDigest: operations.Digest("target"), Class: "source-health", State: readmodel.SourceFailed, Severity: "critical", ObservedAt: now}
	if _, e := s.RecordOperationsObservation(ctx, RevisionToken{}, o, actor, "alerts-github"); e != nil {
		t.Fatal(e)
	}
	due, e := s.DueOperationsDeliveries(ctx, "alerts-github", 0, now)
	if e != nil || len(due) != 1 {
		t.Fatal(due, e)
	}
	d := due[0]
	now = s.config.Clock().UTC().Add(time.Second)
	if e = s.PrepareOperationsDelivery(ctx, d, now); e != nil {
		t.Fatal(e)
	}
	for i := 0; i < audit.MaxDeliveryAttempts; i++ {
		r, e := s.RecordOutboxAttempt(ctx, audit.OutboxAttempt{OutboxID: d.Record.OutboxID, ExpectedAttempt: i, AttemptedAt: now, Retryable: true, ErrorCode: audit.DestinationUnavailable})
		if e != nil {
			t.Fatal(e)
		}
		if r.NextAttemptAt != nil {
			now = *r.NextAttemptAt
		} else if r.Status != audit.OutboxDeadLetter {
			t.Fatal(r)
		}
	}
	due, e = s.DueOperationsDeliveries(ctx, "alerts-github", 0, now)
	if e != nil || len(due) != 0 {
		t.Fatal(due, e)
	}
	alerts, e := s.OperationsAlerts(ctx, RevisionToken{})
	if e != nil || alerts[0].Status != "open" {
		t.Fatal("destination changed local truth", alerts, e)
	}
}
