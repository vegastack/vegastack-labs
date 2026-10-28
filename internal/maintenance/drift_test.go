package maintenance

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"testing"
	"time"
)

func sample(now time.Time) Snapshot {
	return Snapshot{HostID: "host-a", IdentityDigest: hostaction.Digest("host"), BindingDigest: hostaction.Digest("binding"), StateRevision: 4, RecoveryEpoch: 1, RequiredControls: []string{"linux.audit-bounded"}, Controls: []generated.HostControlResult{{HostID: "host-a", IdentityDigest: hostaction.Digest("host"), RecoveryEpoch: 1, ControlID: "linux.audit-bounded", Status: "passed", ObservedAt: now.Format(time.RFC3339)}}, AdmissionPassed: true}
}
func TestDiagnosisRetainsFailureAndRejectsStaleIdentityAndEpoch(t *testing.T) {
	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name, want string
		mutate     func(*Snapshot)
	}{
		{"current", "healthy", func(s *Snapshot) {}},
		{"age-boundary", "healthy", func(s *Snapshot) { s.Controls[0].ObservedAt = now.Add(-24 * time.Hour).Format(time.RFC3339) }},
		{"expired", "stale", func(s *Snapshot) {
			s.Controls[0].ObservedAt = now.Add(-24*time.Hour - time.Second).Format(time.RFC3339)
		}},
		{"failed", "failed", func(s *Snapshot) { s.Controls[0].Status = "failed" }},
		{"partial", "unknown", func(s *Snapshot) { s.Controls[0].Status = "partial" }},
		{"missing", "unknown", func(s *Snapshot) { s.Controls = nil }},
		{"identity", "stale", func(s *Snapshot) { s.Controls[0].IdentityDigest = hostaction.Digest("other") }},
		{"epoch", "stale", func(s *Snapshot) { s.Controls[0].RecoveryEpoch = 0 }},
		{"changed", "stale", func(s *Snapshot) { s.Invalidated = true }},
		{"future", "unknown", func(s *Snapshot) { s.Controls[0].ObservedAt = now.Add(time.Second).Format(time.RFC3339) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := sample(now)
			tc.mutate(&s)
			got, e := Diagnose(s, now)
			if e != nil || got.Status != tc.want || got.ExistingWorkloads != "unchanged" || got.NewAdmissionBlocked != (tc.want != "healthy") {
				t.Fatal(got, e)
			}
		})
	}
	s := sample(now)
	s.AdmissionPassed = false
	got, e := Diagnose(s, now)
	if e != nil || !got.NewAdmissionBlocked || got.Status != "healthy" {
		t.Fatal("controls must not qualify admission", got, e)
	}
}
func TestDiagnosisRejectsUnknownExcludedAndDuplicateTargets(t *testing.T) {
	now := time.Now().UTC()
	for _, id := range []string{"", "vsk-node-04", "vsk-node-05"} {
		s := sample(now)
		s.HostID = id
		if _, e := Diagnose(s, now); e == nil {
			t.Fatal(id)
		}
	}
	s := sample(now)
	s.Controls = append(s.Controls, s.Controls[0])
	if _, e := Diagnose(s, now); e == nil {
		t.Fatal("ambiguous evidence accepted")
	}
}
