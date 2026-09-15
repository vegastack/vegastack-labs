package gate

import (
	"testing"

	"github.com/vegastack/vegastack-labs/internal/store"
)

func TestEvidenceChangeBindsImmutableDraftDigest(t *testing.T) {
	draft := store.GateDraft{DraftID: "draft-evidence-a", EvidenceID: "evidence-a", GateID: "platform-safety", SubjectID: "site-a", BundleDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", StateRevision: 3, RecoveryEpoch: 0}
	request, err := BuildEvidenceChange(draft, store.RevisionToken{StateRevision: 3, RecoveryEpoch: 0})
	if err != nil {
		t.Fatal(err)
	}
	if len(request.Operations) != 1 || request.Operations[0].InputDigest != draft.BundleDigest || request.Operations[0].ArtifactDigest != draft.BundleDigest || request.Operations[0].AdapterID != "core.gate" {
		t.Fatalf("unbound gate operation: %+v", request.Operations)
	}
}

func TestGateOperationCannotMixWithExternalOrUnboundOperation(t *testing.T) {
	profile := store.ProfileDraft{BindingID: "binding-a", Scope: store.GateAppliedProfile{ProfileID: "vegastack-labs"}, ScopeDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", StateRevision: 3}
	request, err := BuildProfileChange(profile, store.RevisionToken{StateRevision: 3})
	if err != nil {
		t.Fatal(err)
	}
	if ValidateGateOperations(request.Operations, false) == nil {
		t.Fatal("external gate plan accepted")
	}
	request.Operations[0].InputDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if ValidateGateOperations(request.Operations, true) == nil {
		t.Fatal("unbound gate input accepted")
	}
}
