package run

import (
	"context"
	"errors"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/hostreplacement"
	"testing"
	"time"
)

func TestResumeAsUsesProjectedHostAndPreservesLegacyTarget(t *testing.T) {
	for _, projected := range []bool{false, true} {
		name := "legacy"
		if projected {
			name = "projected-alias"
		}
		t.Run(name, func(t *testing.T) {
			f := newEngineFixture(t)
			now := f.engine.clock()
			p := f.store.plan
			p.AuthorizationBranch = "human"
			if projected {
				claim := generated.HostAliasClaimRequest{Schema: generated.SchemaIDHostAliasClaimRequest, SchemaVersion: "1.0.0", HostID: "destination-host", HostIdentityDigest: hostaction.Digest("host"), AliasIDs: []string{"alias-a"}, ExpectedStateRevision: p.Binding.PriorStateRevision, RecoveryEpoch: p.Binding.RecoveryEpoch, IdempotencyKey: "claim"}
				if err := hostreplacement.ValidateAliasClaim(claim); err != nil {
					t.Fatal(err)
				}
				d := hostaction.Digest(claim)
				p.HostAliasClaim = &claim
				p.Operations[0].AdapterID = hostreplacement.AdapterID
				p.Operations[0].OperationType = hostreplacement.AliasClaimOperation
				p.Operations[0].TargetID = p.DeclarationID
				p.Operations[0].InputDigest = d
				p.Operations[0].ArtifactDigest = d
			}
			ack := generated.Acknowledgement{Schema: generated.SchemaIDAcknowledgement, SchemaVersion: "1.0.0", AcknowledgementID: "ack-resume", PlanID: p.PlanID, PlanDigest: p.PlanDigest, TargetDigest: p.Binding.TargetDigest, ReasonDigest: p.Binding.ReasonDigest, HumanID: "human-resume", AuthorityID: "authority-resume", NonceDigest: digest("nonce"), ProofDigest: digest("proof"), StateRevision: p.Binding.StateRevision, RecoveryEpoch: p.Binding.RecoveryEpoch, ExpiresAt: now.Add(time.Minute).Format(time.RFC3339), ReceivedAt: now.Format(time.RFC3339), Status: "approved", Extensions: []generated.ContractExtension{}}
			f.store.plan = p
			f.request.Acknowledgement = &ack
			f.request.Authorization.Branch = &p.AuthorizationBranch
			if projected {
				f.request.Authorization.TargetID = "destination-host"
			}
			core := &resumeProjectedCore{}
			gate := NewAdmissionGate(fixedAcknowledgementSource{ack}, f.engine.clock)
			engine, err := NewEngine(Config{Repository: f.store, Plans: f.store, Admission: gate, Adapters: f.engine.adapters, Core: core, Clock: f.engine.clock, IDs: f.engine.ids, LeaseContext: testLeaseContext})
			if err != nil {
				t.Fatal(err)
			}
			engine.testAfterBoundary = func(b Boundary) error {
				if b == BoundaryLeaseAcquired {
					return errors.New("injected interruption before effect")
				}
				return nil
			}
			if _, err = engine.Submit(context.Background(), f.request); err == nil {
				t.Fatal("interruption not exercised")
			}
			engine.testAfterBoundary = nil
			if err = engine.Reconcile(context.Background()); err != nil {
				t.Fatal(err)
			}
			run, err := engine.ResumeAs(context.Background(), f.runID, audit.Attribution{})
			if err != nil || run.Status != "succeeded" {
				t.Fatal("valid resume failed", run.Status, err)
			}
			if projected && core.calls != 1 {
				t.Fatal("projected effect did not resume exactly once", core.calls)
			}
		})
	}
}

type resumeProjectedCore struct{ calls int }

func (c *resumeProjectedCore) Execute(context.Context, ExactStepBinding) (adapter.Effect, error) {
	c.calls++
	return adapter.Effect{Status: "succeeded", Changed: true, EffectObserved: true, ResultDigest: digest("resumed")}, nil
}
func (c *resumeProjectedCore) Verify(context.Context, ExactStepBinding, adapter.Effect) (adapter.Verification, error) {
	return adapter.Verification{Verified: true, Digest: digest("resumed")}, nil
}
