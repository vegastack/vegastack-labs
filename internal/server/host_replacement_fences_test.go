package server

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/recovery"
	"github.com/vegastack/vegastack-labs/internal/store"
	"testing"
	"time"
)

func TestReplacementFenceScopeRequiresEveryKnownCredentialVersion(t *testing.T) {
	s := store.HostReplacementFenceScope{State: generated.HostReplacementState{Status: "frozen"}, Request: generated.HostReplacementRequest{RestorationClass: "stateless-role", OldHostID: "old-host", NewHostID: "new-host", OldIdentityDigest: hostaction.Digest("old")}, AuthorityDigest: hostaction.Digest("authority"), Credentials: []store.HostReplacementCredentialBoundary{{ReferenceID: "credential", ConsumerID: hostaction.AdapterID, PurposeID: hostaction.PurposeID, TargetID: "old-host", ResolverID: "native-systemd", MaterialVersion: "one"}, {ReferenceID: "credential", ConsumerID: hostaction.AdapterID, PurposeID: hostaction.PurposeID, TargetID: "old-host", ResolverID: "native-systemd", MaterialVersion: "two"}}}
	req, e := replacementFenceRequirements(s)
	if e != nil || len(req) != 10 {
		t.Fatalf("%+v %v", req, e)
	}
	if req[2].FormerIdentityID == req[6].FormerIdentityID {
		t.Fatal("versions collapsed")
	}
	s.Credentials[1].PurposeID = "unsupported-provider"
	if _, e = replacementFenceRequirements(s); e == nil {
		t.Fatal("unknown consumer silently omitted")
	}
	s.Credentials = nil
	s.Outstanding = []store.HostReplacementOutstanding{{RunID: "run", EffectState: "uncertain"}}
	if _, e = replacementFenceRequirements(s); e == nil {
		t.Fatal("uncertain work admitted")
	}
	s.Outstanding = nil
	s.Request.OldHostID = "vsk-node-04"
	if _, e = replacementFenceRequirements(s); e == nil {
		t.Fatal("protected target admitted")
	}
}

// An unchecked verifier registration cannot cross the private qualified seam.
// A nil backing store makes any accidental persistence before validation fail.
func TestReplacementFencePrivateSeamRejectsUnsealedRegistryBeforeStore(t *testing.T) {
	repo := store.NewHostReplacementRepository(nil)
	q := recovery.NewQualifiedAdapters()
	q.Register("https-direct-denial-v1", uncheckedReplacementDenial{})
	if _, err := verifyReplacementFencesWithQualified(context.Background(), repo, store.HostReplacementExecution{}, time.Now().UTC(), q); err == nil {
		t.Fatal("unchecked verifier reached persistence")
	}
}

type uncheckedReplacementDenial struct{}

func (uncheckedReplacementDenial) VerifyDirectDenial(context.Context, recovery.DirectDenialTranscript) error {
	return nil
}
