package recovery

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type suffixReaderStub struct {
	reads, providerExecutions int
	value                     store.CanonicalAuditSuffix
	err                       error
}

func (stub *suffixReaderStub) ReadAuditSuffix(context.Context, audit.EventID, audit.EventID) (store.CanonicalAuditSuffix, error) {
	stub.reads++
	return stub.value, stub.err
}

type lossAckStub struct {
	calls int
	err   error
}

func (stub *lossAckStub) VerifyAuditLoss(context.Context, generated.RestoreAuditDecision) error {
	stub.calls++
	return stub.err
}

func TestRecoveredAuditSuffixNeverReplaysEffects(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	suffixDigest := audit.Fingerprint("sha256:" + strings.Repeat("b", 64))
	events, links := validSuffix(t, 5, 6)
	rangeDigest, err := audit.DigestChainRange(links)
	if err != nil {
		t.Fatal(err)
	}
	reader := &suffixReaderStub{value: store.CanonicalAuditSuffix{Events: events, Chain: audit.ChainRange{FirstEventID: 5, LastEventID: 6, Links: links, RangeDigest: rangeDigest}, Digest: suffixDigest}}
	source := VerifiedSource{Audit: AuditContinuity{LocalLastEventID: 4, IndependentLastEventID: 6, IndependentCheckpointDigest: digest}}
	decision := generated.RestoreAuditDecision{Schema: generated.SchemaIDRestoreAuditDecision, SchemaVersion: "1.1.0", LocalLastEventID: 4, IndependentLastEventID: 6, IndependentCheckpointDigest: digest, Strategy: "recovered-suffix"}
	decision.DecisionDigest = auditDecisionDigest("recovered-suffix", 4, 6, digest, string(suffixDigest), nil)
	got, err := (ContinuityResolver{Suffix: reader}).Resolve(context.Background(), source, &decision)
	if err != nil {
		t.Fatal(err)
	}
	if got.Strategy != "recovered-suffix" || got.RecoveredSuffixDigest != string(suffixDigest) || reader.reads != 1 || reader.providerExecutions != 0 {
		t.Fatalf("got=%#v reader=%#v", got, reader)
	}
}

func validSuffix(t *testing.T, firstID, lastID int64) ([]audit.Event, []audit.ChainLink) {
	t.Helper()
	previous := audit.Fingerprint("sha256:" + strings.Repeat("c", 64))
	var events []audit.Event
	var links []audit.ChainLink
	for id := firstID; id <= lastID; id++ {
		event := audit.Event{Schema: audit.EventSchema, SchemaVersion: audit.EventSchemaVersion, EventID: audit.EventID(id), OccurredAt: time.Date(2026, 9, 23, 11, int(id), 0, 0, time.UTC).Format(time.RFC3339Nano), RecoveryEpoch: 3, StateRevision: 8, Type: "recovery.audit.suffix", CorrelationID: "correlation-a", PrincipalID: "principal-a", PrincipalMethod: "local-os-peer", Target: audit.Target{Kind: "audit", ID: "history-a"}}
		link, err := audit.MakeChainLink(event, audit.ContextIDs{}, "instance-a", id, previous, false)
		if err != nil {
			t.Fatal(err)
		}
		events, links, previous = append(events, event), append(links, link), link.LinkDigest
	}
	return events, links
}

func TestCheckpointAheadRequiresExactDecision(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	source := VerifiedSource{Audit: AuditContinuity{LocalLastEventID: 4, IndependentLastEventID: 8, IndependentCheckpointDigest: digest}}
	resolver := ContinuityResolver{}
	if _, err := resolver.Resolve(context.Background(), source, nil); err == nil {
		t.Fatal("checkpoint-ahead source admitted without decision")
	}
	fromID, throughID := int64(5), int64(8)
	from, through, ack := "2026-09-23T11:00:00Z", "2026-09-23T11:30:00Z", "ack-a"
	lost := &LostInterval{FromEventID: fromID, ThroughEventID: throughID, From: mustTime(t, from), Through: mustTime(t, through), HumanAcknowledgementID: ack}
	decision := generated.RestoreAuditDecision{Schema: generated.SchemaIDRestoreAuditDecision, SchemaVersion: "1.1.0", LocalLastEventID: 4, IndependentLastEventID: 8, IndependentCheckpointDigest: digest, Strategy: "accepted-loss", LostFromEventID: &fromID, LostThroughEventID: &throughID, LostFromTime: &from, LostThroughTime: &through, HumanAcknowledgementID: &ack}
	decision.DecisionDigest = auditDecisionDigest("accepted-loss", 4, 8, digest, "", lost)
	verifier := &lossAckStub{}
	got, err := (ContinuityResolver{Acknowledgements: verifier}).Resolve(context.Background(), source, &decision)
	if err != nil {
		t.Fatal(err)
	}
	if got.Strategy != "accepted-loss" || got.LostInterval == nil || verifier.calls != 1 {
		t.Fatalf("got=%#v calls=%d", got, verifier.calls)
	}
	wrong := throughID + 1
	decision.LostThroughEventID = &wrong
	if _, err := (ContinuityResolver{Acknowledgements: verifier}).Resolve(context.Background(), source, &decision); err == nil {
		t.Fatal("wrong lost interval accepted")
	}
}

func mustTime(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}
