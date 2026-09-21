package recoverydenial

import (
	"context"
	"testing"
	"time"
)

func TestDirectDenialResultBindsChallenge(t *testing.T) {
	now := time.Date(2026, 9, 22, 0, 0, 0, 0, time.UTC)
	challenge := Challenge{ChallengeID: "nonce-1", Kind: "provider-mutation", SubjectID: "subject-1", TargetID: "target-1", AdapterID: "adapter-1", FormerIdentityID: "old-identity", ProbeID: "mutation-denied", Deadline: now.Add(20 * time.Second)}
	result := Result{ChallengeID: challenge.ChallengeID, Kind: challenge.Kind, SubjectID: challenge.SubjectID, TargetID: challenge.TargetID, AdapterID: challenge.AdapterID, FormerIdentityID: challenge.FormerIdentityID, ProbeID: challenge.ProbeID, ObserverID: "custodian-observer", ResponseClass: "direct-denial", ResponseDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ObservedAt: now, ExpiresAt: now.Add(10 * time.Second), SessionExpiry: now.Add(10 * time.Second), Denied: true}
	if err := ValidateResult(context.Background(), challenge, result, now); err != nil {
		t.Fatal(err)
	}
	changed := result
	changed.ChallengeID = "other"
	if err := ValidateResult(context.Background(), challenge, changed, now); err == nil {
		t.Fatal("wrong challenge accepted")
	}
	changed = result
	changed.Denied = false
	if err := ValidateResult(context.Background(), challenge, changed, now); err == nil {
		t.Fatal("admitted old identity accepted")
	}
	changed = result
	changed.ResponseClass = "stopped"
	if err := ValidateResult(context.Background(), challenge, changed, now); err == nil {
		t.Fatal("generic status accepted")
	}
	changed = result
	changed.ObserverID = ""
	if err := ValidateResult(context.Background(), challenge, changed, now); err == nil {
		t.Fatal("missing independent observer accepted")
	}
	changed = result
	changed.Kind = "mesh"
	if err := ValidateResult(context.Background(), challenge, changed, now); err == nil {
		t.Fatal("wrong boundary kind accepted")
	}
	changed = result
	changed.SessionExpiry = now.Add(-time.Second)
	if err := ValidateResult(context.Background(), challenge, changed, now); err == nil {
		t.Fatal("expired former session accepted")
	}
	if err := ValidateResult(context.Background(), challenge, result, now.Add(11*time.Second)); err == nil {
		t.Fatal("stale result accepted")
	}
}
