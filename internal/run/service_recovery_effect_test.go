package run

import (
	"context"
	"errors"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/servicerecovery"
	"testing"
	"time"
)

// Exercise the existing engine's dispatch and durable interruption handling:
// recovery is a non-idempotent core operation, never a generic adapter retry.
func TestRecoveryCoreEngineNeverReplaysAmbiguousAttempt(t *testing.T) {
	f := newEngineFixture(t)
	now := f.engine.clock()
	p := f.store.plan
	p.AuthorizationBranch = "human"
	p.Risk = "production-like"
	p.Operations[0].AdapterID = servicerecovery.AdapterID
	p.Operations[0].OperationType = servicerecovery.Operation
	p.Operations[0].Idempotent = false
	p.Operations[0].ArtifactDigest = p.Operations[0].InputDigest
	ack := generated.Acknowledgement{Schema: generated.SchemaIDAcknowledgement, SchemaVersion: "1.0.0", AcknowledgementID: "recovery-ack", PlanID: p.PlanID, PlanDigest: p.PlanDigest, TargetDigest: p.Binding.TargetDigest, ReasonDigest: p.Binding.ReasonDigest, HumanID: "human-recovery", AuthorityID: "authority-recovery", NonceDigest: digest("nonce"), ProofDigest: digest("proof"), StateRevision: p.Binding.StateRevision, RecoveryEpoch: p.Binding.RecoveryEpoch, ExpiresAt: now.Add(time.Minute).Format(time.RFC3339), ReceivedAt: now.Format(time.RFC3339), Status: "approved", Extensions: []generated.ContractExtension{}}
	f.store.plan = p
	f.request.Acknowledgement = &ack
	f.request.Authorization.Branch = &p.AuthorizationBranch
	core := &resumeProjectedCore{}
	engine, err := NewEngine(Config{Repository: f.store, Plans: f.store, Admission: NewAdmissionGate(fixedAcknowledgementSource{ack}, f.engine.clock), Adapters: f.engine.adapters, Core: CoreRouter{ServiceRecovery: core}, Clock: f.engine.clock, IDs: f.engine.ids, LeaseContext: testLeaseContext})
	if err != nil {
		t.Fatal(err)
	}
	engine.testAfterBoundary = func(b Boundary) error {
		if b == BoundaryEffectReturned {
			return errors.New("lost recovery response")
		}
		return nil
	}
	if _, err = engine.Submit(context.Background(), f.request); err == nil || core.calls != 1 || f.adapter.calls != 0 {
		t.Fatal("recovery core dispatch failed", core.calls, f.adapter.calls, err)
	}
	engine.testAfterBoundary = nil
	if err = engine.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	result, err := engine.Get(context.Background(), f.runID)
	if err != nil || result.Status != "partial" {
		t.Fatal("uncertain recovery not partial", result.Status, err)
	}
	if _, err = engine.ResumeAs(context.Background(), f.runID, audit.Attribution{}); err == nil {
		t.Fatal("non-idempotent recovery resumed")
	}
	if core.calls != 1 {
		t.Fatal("recovery repeated", core.calls)
	}
}
