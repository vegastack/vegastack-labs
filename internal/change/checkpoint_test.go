package change

import (
	"testing"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/store"
)

func TestCheckpointChangeBindsExactRange(t *testing.T) {
	digest := audit.Fingerprint("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	chain := audit.ChainRange{FirstEventID: 1, LastEventID: 2, RangeDigest: digest, Links: []audit.ChainLink{{EventID: 1, InstanceID: "instance-a", RecoveryEpoch: 2, SegmentSequence: 1, LinkDigest: digest}, {EventID: 2, InstanceID: "instance-a", RecoveryEpoch: 2, SegmentSequence: 2, LinkDigest: digest}}}
	request, err := BuildCheckpointChange(chain, store.RevisionToken{StateRevision: 4, RecoveryEpoch: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(request.Operations) != 1 || request.Operations[0].AdapterID != "core.audit" || request.Operations[0].InputDigest != string(digest) || request.Operations[0].ArtifactDigest != string(digest) || len(request.Extensions) != 1 || request.Extensions[0].ValueDigest != string(digest) {
		t.Fatalf("unbound checkpoint change: %+v", request)
	}
}
