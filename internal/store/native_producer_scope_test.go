package store

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"testing"
	"time"
)

func TestNativeProducerLookupProtectedScope(t *testing.T) {
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	scope := generated.QualificationScope{ControllerInstanceID: "prior", IssuedAt: now.Add(-time.Minute).Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), Guests: []generated.QualificationGuest{{HostID: "old", HostIdentityDigest: hostaction.Digest("old")}, {HostID: "new", HostIdentityDigest: hostaction.Digest("new")}}}
	snapshot := NativeProducerSnapshot{ControllerInstanceID: "prior", Producers: []generated.NativeQualificationProducer{{HostIdentityDigest: scope.Guests[1].HostIdentityDigest}}}
	in := generated.NativeProducerLookupRequest{HostID: "new", ScopeDigest: hostaction.Digest(scope)}
	if !nativeLookupScopeMatches(scope, in, snapshot, now) {
		t.Fatal("current scope denied")
	}
	snapshot.ControllerInstanceID = "next"
	snapshot.Revision.RecoveryEpoch = 1
	if nativeLookupScopeMatches(scope, in, snapshot, now) {
		t.Fatal("new controller without verified restore accepted")
	}
	snapshot.VerifiedRestoreBinding = &generated.RestoreBinding{PriorInstanceID: "prior", NewInstanceID: "next", FormerHostID: "old", ReplacementHostID: "new", PriorRecoveryEpoch: 0, NextRecoveryEpoch: 1}
	if !nativeLookupScopeMatches(scope, in, snapshot, now) {
		t.Fatal("verified current restore denied")
	}
	for _, variant := range []string{"expired", "future", "wrong-controller", "wrong-identity", "wrong-digest", "wrong-epoch", "absent-former"} {
		t.Run(variant, func(t *testing.T) {
			s := scope
			s.Guests = append([]generated.QualificationGuest(nil), scope.Guests...)
			snap := snapshot
			req := in
			switch variant {
			case "expired":
				s.ExpiresAt = now.Format(time.RFC3339)
			case "future":
				s.IssuedAt = now.Add(time.Second).Format(time.RFC3339)
			case "wrong-controller":
				s.ControllerInstanceID = "stranger"
			case "wrong-identity":
				s.Guests[1].HostIdentityDigest = hostaction.Digest("substitute")
			case "wrong-epoch":
				snap.Revision.RecoveryEpoch++
			case "absent-former":
				s.Guests = s.Guests[1:]
			}
			req.ScopeDigest = hostaction.Digest(s)
			if variant == "wrong-digest" {
				req.ScopeDigest = hostaction.Digest("wrong")
			}
			if nativeLookupScopeMatches(s, req, snap, now) {
				t.Fatal("scope substitution accepted")
			}
		})
	}
}
