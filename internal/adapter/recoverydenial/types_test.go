package recoverydenial

import (
	"context"
	"testing"
	"time"
)

func TestDirectDenialResultBindsChallenge(t *testing.T) {
	now := time.Date(2026, 9, 22, 0, 0, 0, 0, time.UTC)
	challenge := Challenge{ChallengeID: "nonce-1", TargetID: "target-1", FormerIdentityID: "old-identity", ProbeID: "mutation-denied", Deadline: now.Add(20 * time.Second)}
	result := Result{ChallengeID: challenge.ChallengeID, TargetID: challenge.TargetID, FormerIdentityID: challenge.FormerIdentityID, ProbeID: challenge.ProbeID, ResponseClass: "direct-denial", ResponseDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ObservedAt: now, ExpiresAt: now.Add(10 * time.Second), Denied: true}
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
	if err := ValidateResult(context.Background(), challenge, result, now.Add(11*time.Second)); err == nil {
		t.Fatal("stale result accepted")
	}
}
