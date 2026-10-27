package hostaction

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"testing"
)

func TestCIJobRequiresTypedControlAndExactCredentialSet(t *testing.T) {
	a := &Adapter{}
	if e := a.ConfigureCI(nil); e == nil {
		t.Fatal("nil control source accepted")
	}
	op := adapter.Operation{OperationID: "ci-job", OperationType: "ci.job.execute", AdapterID: "host-action", ExecutorID: "central", TargetID: "host-a", InputDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ArtifactDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
	if e, err := a.ExecuteBoundWithCredentials(context.Background(), op, adapter.ExactExecutionBinding{}, nil); err == nil || e.EffectObserved {
		t.Fatal("unsigned missing credentials executed", e, err)
	}
	if _, _, e := a.exchangeOne(context.Background(), Target{}, generated.HostActionEnvelope{}, "", nil, nil, nil, nil, "", nil); e == nil {
		t.Fatal("unpinned target accepted")
	}
}
