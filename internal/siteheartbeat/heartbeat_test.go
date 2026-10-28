package siteheartbeat

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func TestEncodedHeartbeatMatchesConsumerFixtureAndRejectsStaleInput(t *testing.T) {
	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	snapshot := Snapshot{SiteDigest: "sha256:" + strings.Repeat("a", 64), ObservedAt: now, StateRevision: 7, RecoveryEpoch: 2}
	data, err := Encode(snapshot, now)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("testdata/heartbeat.json")
	if err != nil || string(data)+"\n" != string(want) {
		t.Fatalf("fixture mismatch: %s %v", data, err)
	}
	snapshot.ObservedAt = now.Add(-2 * time.Minute)
	if _, err = Encode(snapshot, now); err == nil {
		t.Fatal("stale cached health accepted")
	}
	snapshot.ObservedAt = now.Add(time.Minute)
	if _, err = Encode(snapshot, now); err == nil {
		t.Fatal("future health accepted")
	}
	snapshot.ObservedAt = now
	snapshot.SiteDigest = "private-domain-secret"
	if _, err = Encode(snapshot, now); err == nil || strings.Contains(err.Error(), "private-domain") {
		t.Fatal("unsafe site identity accepted or leaked")
	}
}

type source struct {
	calls    int
	snapshot Snapshot
	err      error
}

func (s *source) HeartbeatSnapshot(context.Context) (Snapshot, error) {
	s.calls++
	return s.snapshot, s.err
}

type writer struct{ calls int }

func (w *writer) WriteHeartbeat(context.Context, []byte) error { w.calls++; return nil }
func TestPublisherRequiresFreshSuccessfulAuthorityRead(t *testing.T) {
	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	s := &source{snapshot: Snapshot{SiteDigest: "sha256:" + strings.Repeat("a", 64), ObservedAt: now.Add(-time.Hour)}}
	w := &writer{}
	p := Publisher{Source: s, Writer: w, Clock: func() time.Time { return now }}
	if p.Publish(context.Background()) == nil || w.calls != 0 {
		t.Fatal("stale cache published")
	}
	s.snapshot.ObservedAt = now
	if err := p.Publish(context.Background()); err != nil || w.calls != 1 || s.calls != 2 {
		t.Fatal("current health not published")
	}
}
