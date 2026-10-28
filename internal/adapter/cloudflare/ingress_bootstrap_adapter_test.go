package cloudflare

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	ingress "github.com/vegastack/vegastack-labs/internal/networkingress"
	"testing"
)

type bootstrapAuthorityFixture struct {
	d        ingress.Staged
	denied   bool
	reserved bool
	records  []string
}

func (a *bootstrapAuthorityFixture) Resolve(context.Context, adapter.Operation, adapter.ExactExecutionBinding) (ingress.Staged, error) {
	if a.denied {
		return ingress.Staged{}, ingress.Error(generated.ErrorCodeAuthorizationDenied)
	}
	return a.d, nil
}
func (a *bootstrapAuthorityFixture) BorrowRead(context.Context, ingress.Staged) (*credentialref.Value, error) {
	return credentialref.NewValue([]byte("fixture-reader"))
}
func (a *bootstrapAuthorityFixture) Record(_ context.Context, _ ingress.Staged, _ adapter.ExactExecutionBinding, _ ingress.Snapshot, status string) error {
	a.records = append(a.records, status)
	return nil
}
func (a *bootstrapAuthorityFixture) ReserveBootstrap(context.Context, ingress.Staged, adapter.ExactExecutionBinding, ingress.Snapshot) error {
	if a.reserved {
		return ingress.Error(generated.ErrorCodeStateConflict)
	}
	a.reserved = true
	return nil
}

type bootstrapBackendFixture struct {
	writes, reads, dnsWrites int
	lost                     bool
	changed                  bool
}

func (b *bootstrapBackendFixture) ObserveIngress(context.Context, generated.IngressChange, *credentialref.Value) (ingress.Snapshot, error) {
	panic("ordinary ingress path used for bootstrap")
}
func (b *bootstrapBackendFixture) MutateIngress(context.Context, generated.IngressChange, *credentialref.Value, *credentialref.Value, *credentialref.Value) error {
	panic("ordinary mutation used for bootstrap")
}
func (b *bootstrapBackendFixture) ObserveBootstrap(_ context.Context, q generated.IngressChange, _ *credentialref.Value) (ingress.Snapshot, error) {
	b.reads++
	if q.ResourceID == "" {
		return ingress.Snapshot{Digest: ingress.Digest("before")}, nil
	}
	d := ingress.Digest(q.ResourceID)
	if b.changed {
		d = ingress.Digest("changed")
	}
	return ingress.Snapshot{Present: true, ResourceID: q.ResourceID, Digest: d}, nil
}
func (b *bootstrapBackendFixture) MutateBootstrap(_ context.Context, q generated.IngressChange, _, _ *credentialref.Value) (ingress.Snapshot, error) {
	b.writes++
	if q.Action == "bootstrap-cutover" {
		b.dnsWrites++
	}
	if b.lost {
		return ingress.Snapshot{}, ingress.Error(generated.ErrorCodeDependencyUnavailable)
	}
	return ingress.Snapshot{Present: true, ResourceID: testUUID, Digest: ingress.Digest(testUUID)}, nil
}
func bootstrapAdapterFixture(t *testing.T) (*IngressAdapter, *bootstrapAuthorityFixture, *bootstrapBackendFixture, adapter.Operation, []*credentialref.Value) {
	t.Helper()
	q := generated.IngressChange{ProfileID: "bootstrap", Action: "bootstrap-tunnel", Bootstrap: &generated.IngressBootstrap{}, BeforeDigest: ingress.Digest("before")}
	authority := &bootstrapAuthorityFixture{d: ingress.Staged{Request: generated.IngressDraftRequest{Change: q}, Bindings: []credentialref.StepBinding{{PurposeID: ingress.PurposeRead}, {PurposeID: ingress.PurposeWrite}}}}
	backend := &bootstrapBackendFixture{}
	op := adapter.Operation{OperationID: ingress.OperationID, OperationType: "network.ingress.bootstrap-tunnel", AdapterID: ingress.AdapterID, ExecutorID: "central", TargetID: q.ProfileID, InputDigest: ingress.Digest("bindings"), ArtifactDigest: ingress.Digest("request")}
	return &IngressAdapter{Authority: authority, Backend: backend}, authority, backend, op, []*credentialref.Value{testValue(t, "fixture-reader"), testValue(t, "fixture-writer")}
}
func TestBootstrapStagesReserveAndVerifyBeforeRecording(t *testing.T) {
	for _, action := range ingress.BootstrapActions {
		t.Run(action, func(t *testing.T) {
			a, authority, b, op, values := bootstrapAdapterFixture(t)
			authority.d.Request.Change.Action = action
			op.OperationType = "network.ingress." + action
			effect, e := a.ExecuteBoundWithCredentials(context.Background(), op, adapter.ExactExecutionBinding{RunID: "run-a", StepID: "step-a"}, values)
			if e != nil || effect.Status != "succeeded" || !authority.reserved || b.writes != 1 || len(authority.records) != 0 {
				t.Fatalf("effect%+v err%v reserved%v writes%d", effect, e, authority.reserved, b.writes)
			}
			if action != "bootstrap-cutover" && b.dnsWrites != 0 {
				t.Fatal("setup published DNS")
			}
			verified, e := a.Verify(context.Background(), op, effect)
			if e != nil || !verified.Verified || len(authority.records) != 1 || authority.records[0] != "observed" {
				t.Fatalf("verification %+v %v records%v", verified, e, authority.records)
			}
		})
	}
}
func TestBootstrapUnknownCompletionNeverBlindlyRetries(t *testing.T) {
	a, authority, b, op, values := bootstrapAdapterFixture(t)
	b.lost = true
	effect, e := a.ExecuteBoundWithCredentials(context.Background(), op, adapter.ExactExecutionBinding{RunID: "run-a", StepID: "step-a"}, values)
	if e != nil || effect.Status != "partial" || b.writes != 1 || !authority.reserved || authority.records[0] != "partial" {
		t.Fatalf("lost completion %+v %v", effect, e)
	}
	if _, e = a.ExecuteBoundWithCredentials(context.Background(), op, adapter.ExactExecutionBinding{RunID: "run-b", StepID: "step-a"}, values); e == nil || b.writes != 1 {
		t.Fatal("uncertain create blindly retried")
	}
}
func TestBootstrapDeniedAuthorityAndStaleObservationNeverWrite(t *testing.T) {
	for _, variant := range []string{"denied", "stale", "missing-writer"} {
		t.Run(variant, func(t *testing.T) {
			a, authority, b, op, values := bootstrapAdapterFixture(t)
			switch variant {
			case "denied":
				authority.denied = true
			case "stale":
				authority.d.Request.Change.BeforeDigest = ingress.Digest("different")
			case "missing-writer":
				authority.d.Bindings = authority.d.Bindings[:1]
				values = values[:1]
			}
			if _, e := a.ExecuteBoundWithCredentials(context.Background(), op, adapter.ExactExecutionBinding{}, values); e == nil || b.writes != 0 || authority.reserved {
				t.Fatalf("denied operation wrote provider (%d)", b.writes)
			}
		})
	}
}
