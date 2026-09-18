package audit

import (
	"strings"
	"testing"
)

func chainEventFixture(t *testing.T) Event {
	t.Helper()
	return publicFixtureEvent(t)
}

func testGenesisDigest() Fingerprint {
	return Fingerprint("sha256:" + strings.Repeat("1", 64))
}

func testOtherDigest() Fingerprint {
	return Fingerprint("sha256:" + strings.Repeat("2", 64))
}

func TestChainBindsOrderInstanceEpochAndContext(t *testing.T) {
	event := chainEventFixture(t)
	base, err := MakeChainLink(event, ContextIDs{RunID: "run-a", PlanID: "plan-a"}, "instance-a", 1, testGenesisDigest(), false)
	if err != nil {
		t.Fatal(err)
	}
	type variant struct {
		event     Event
		ids       ContextIDs
		instance  string
		sequence  int64
		previous  Fingerprint
		preAnchor bool
	}
	variants := []variant{
		{event, ContextIDs{RunID: "run-a", PlanID: "plan-a"}, "instance-a", 1, testOtherDigest(), false},
		{event, ContextIDs{RunID: "run-a", PlanID: "plan-a"}, "instance-b", 1, testGenesisDigest(), false},
		{event, ContextIDs{RunID: "run-b", PlanID: "plan-a"}, "instance-a", 1, testGenesisDigest(), false},
		{event, ContextIDs{RunID: "run-a", PlanID: "plan-a"}, "instance-a", 2, testGenesisDigest(), false},
		{event, ContextIDs{RunID: "run-a", PlanID: "plan-a"}, "instance-a", 1, testGenesisDigest(), true},
	}
	epochChanged := event
	epochChanged.RecoveryEpoch++
	variants = append(variants, variant{epochChanged, ContextIDs{RunID: "run-a", PlanID: "plan-a"}, "instance-a", 1, testGenesisDigest(), false})
	for _, variant := range variants {
		changed, err := MakeChainLink(variant.event, variant.ids, variant.instance, variant.sequence, variant.previous, variant.preAnchor)
		if err != nil || changed.LinkDigest == base.LinkDigest {
			t.Fatal("chain binding lost", err)
		}
	}
	if !ValidFingerprint(base.LinkDigest) || base.PayloadDigest == "" || base.ContextDigest == "" {
		t.Fatal("missing valid chain digests")
	}
	repeated, err := MakeChainLink(event, ContextIDs{RunID: "run-a", PlanID: "plan-a"}, "instance-a", 1, testGenesisDigest(), false)
	if err != nil || repeated != base {
		t.Fatal("non-deterministic chain link", err)
	}
	_, canonicalDigest, err := CanonicalEvent(event)
	if err != nil || base.PayloadDigest != canonicalDigest {
		t.Fatal("chain lost canonical v1.0 payload binding", err)
	}
}

func TestChainRejectsUnboundedOrSecretLikeContext(t *testing.T) {
	for _, ids := range []ContextIDs{
		{ProviderNativeID: "secret\nvalue"},
		{RunID: strings.Repeat("r", 129)},
		{PlanID: "ghp_looks-like-a-token"},
	} {
		if _, _, err := CanonicalContext(ids); err == nil {
			t.Fatalf("unbounded context accepted: %#v", ids)
		}
	}
	event := chainEventFixture(t)
	for _, candidate := range []struct {
		instance string
		sequence int64
		previous Fingerprint
	}{
		{"", 1, testGenesisDigest()},
		{"instance-a", 0, testGenesisDigest()},
		{"instance-a", 1, "sha256:bad"},
	} {
		if _, err := MakeChainLink(event, ContextIDs{}, candidate.instance, candidate.sequence, candidate.previous, false); err == nil {
			t.Fatal("invalid chain input accepted")
		}
	}
}

func TestGenesisBindsPriorCheckpointAndRecoveryDecision(t *testing.T) {
	base := GenesisLink("instance-a", 1, testGenesisDigest(), testOtherDigest())
	if !ValidFingerprint(base.LinkDigest) || base.EventID != 0 || base.SegmentSequence != 0 {
		t.Fatal("invalid genesis link")
	}
	if base.PriorCheckpoint != testGenesisDigest() || base.RecoveryDecision != testOtherDigest() {
		t.Fatal("genesis cannot be independently reconstructed")
	}
	for _, changed := range []ChainLink{
		GenesisLink("instance-b", 1, testGenesisDigest(), testOtherDigest()),
		GenesisLink("instance-a", 2, testGenesisDigest(), testOtherDigest()),
		GenesisLink("instance-a", 1, testOtherDigest(), testOtherDigest()),
		GenesisLink("instance-a", 1, testGenesisDigest(), testGenesisDigest()),
	} {
		if changed.LinkDigest == base.LinkDigest {
			t.Fatal("genesis binding lost")
		}
	}
	if ValidFingerprint(GenesisLink("", 1, testGenesisDigest(), testOtherDigest()).LinkDigest) {
		t.Fatal("invalid genesis accepted")
	}
}
