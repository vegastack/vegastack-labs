package recovery

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/adapter/recoverydenial"
	"strings"
	"testing"
	"time"
)

type hostProbeFixture struct {
	at     time.Time
	mutate func(*recoverydenial.Result)
}

func (p hostProbeFixture) VerifyDirectDenial(context.Context, DirectDenialTranscript) error {
	return ErrWitnessUnavailable
}
func (p hostProbeFixture) probeHostGeneration(_ context.Context, c recoverydenial.Challenge) (recoverydenial.Result, error) {
	r := recoverydenial.Result{ChallengeID: c.ChallengeID, Kind: c.Kind, SubjectID: c.SubjectID, TargetID: c.TargetID, AdapterID: c.AdapterID, FormerIdentityID: c.FormerIdentityID, ProbeID: c.ProbeID, ObserverID: "independent-consumer", ResponseClass: "direct-denial", ResponseDigest: "sha256:" + strings.Repeat("a", 64), ObservedAt: p.at, ExpiresAt: c.Deadline, SessionExpiry: c.Deadline, Denied: true}
	if p.mutate != nil {
		p.mutate(&r)
	}
	return r, nil
}
func hostFenceFixture() (HostGenerationFenceBinding, []BoundaryRequirement, QualifiedAdapters, time.Time) {
	at := time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC)
	d := "sha256:" + strings.Repeat("a", 64)
	required := []BoundaryRequirement{{Kind: "ssh", SubjectID: "old", TargetID: "consumer", AdapterID: "adapter", FormerIdentityID: "credential", ProbeID: "new-auth-denied"}, {Kind: "ssh", SubjectID: "old", TargetID: "consumer", AdapterID: "adapter", FormerIdentityID: "credential", ProbeID: "open-session-denied"}}
	rd, _ := HostGenerationRequirementsDigest(required)
	b := HostGenerationFenceBinding{ReplacementID: "replace", ControllerInstanceID: "controller", OldHostID: "old", NewHostID: "new", OldIdentityDigest: d, NewIdentityDigest: "sha256:" + strings.Repeat("b", 64), FrozenAliasesDigest: d, AuthorityDigest: d, PlanID: "plan", PlanDigest: d, RunID: "run", StepID: "step", LeaseID: "lease", RequirementsDigest: rd, QualificationDigest: d, Nonce: "persisted-nonce", ReceiptID: "receipt", RecoveryEpoch: 2, PriorGeneration: 1, NextGeneration: 2, IssuedAt: at, Deadline: at.Add(time.Minute)}
	q := QualifiedAdapters{sourceQualified: true, qualificationDigest: d, qualificationExpiry: at.Add(time.Hour), adminRootDigest: d, entries: map[string]DirectDenialVerifier{"adapter": hostProbeFixture{at: at}}}
	return b, required, q, at
}
func TestHostGenerationFenceExactCurrentBoundary(t *testing.T) {
	b, r, q, at := hostFenceFixture()
	got, e := VerifyHostGenerationFences(context.Background(), b, r, q, at)
	if e != nil || len(got.Transcripts) != 2 || got.Binding.RecoveryEpoch != 2 || got.Digest == "" {
		t.Fatalf("%+v %v", got, e)
	}
	for name, change := range map[string]func(*HostGenerationFenceBinding){"generation": func(b *HostGenerationFenceBinding) { b.NextGeneration++ }, "same-host": func(b *HostGenerationFenceBinding) { b.NewHostID = b.OldHostID }, "expired": func(b *HostGenerationFenceBinding) { b.Deadline = at }, "qualification": func(b *HostGenerationFenceBinding) { b.QualificationDigest = b.NewIdentityDigest }} {
		t.Run(name, func(t *testing.T) {
			copy := b
			change(&copy)
			if _, e := VerifyHostGenerationFences(context.Background(), copy, r, q, at); e == nil {
				t.Fatal("invalid binding passed")
			}
		})
	}
	if _, e := VerifyHostGenerationFences(context.Background(), b, r[:1], q, at); e == nil {
		t.Fatal("partial probes passed")
	}
	q.Register("adapter", hostProbeFixture{at: at})
	if _, e := VerifyHostGenerationFences(context.Background(), b, r, q, at); e == nil {
		t.Fatal("unsealed factory passed")
	}
}
func TestHostGenerationFenceRejectsReplayAndSelfObservation(t *testing.T) {
	for name, change := range map[string]func(*recoverydenial.Result){"self": func(r *recoverydenial.Result) { r.ObserverID = "controller" }, "old": func(r *recoverydenial.Result) { r.ObserverID = "old" }, "replay": func(r *recoverydenial.Result) { r.ChallengeID = "prior" }, "allowed": func(r *recoverydenial.Result) { r.Denied = false }, "stale": func(r *recoverydenial.Result) { r.ObservedAt = r.ObservedAt.Add(-time.Second) }} {
		t.Run(name, func(t *testing.T) {
			b, r, q, at := hostFenceFixture()
			q.entries["adapter"] = hostProbeFixture{at: at, mutate: change}
			if _, e := VerifyHostGenerationFences(context.Background(), b, r, q, at); e == nil {
				t.Fatal("invalid observation passed")
			}
		})
	}
	b, _, _, _ := hostFenceFixture()
	first := HostGenerationChallengeID(b)
	b.LeaseID = "other"
	if first == HostGenerationChallengeID(b) {
		t.Fatal("challenge does not bind execution")
	}
}
