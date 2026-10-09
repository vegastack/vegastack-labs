package plan

import (
	"context"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/hostreplacement"
	"strings"
	"testing"
)

func TestAliasClaimPlanBindsTypedOwnerAndRejectsBroadening(t *testing.T) {
	claim := generated.HostAliasClaimRequest{Schema: generated.SchemaIDHostAliasClaimRequest, SchemaVersion: "1.0.0", HostID: "host-one", HostIdentityDigest: testDigestString("a"), AliasIDs: []string{"alias-one"}, ExpectedStateRevision: 9, RecoveryEpoch: 2, IdempotencyKey: "claim-one"}
	digest := hostaction.Digest(claim)
	d := generated.DeclarationRevision{DeclarationID: "declaration-one", DeclarationType: "host.alias-claim", RecoveryEpoch: 2, HostAliasClaim: &claim, Extensions: []generated.ContractExtension{{Name: hostreplacement.AliasClaimExtension, ValueDigest: digest}}}
	ops := []generated.PlanOperation{{OperationType: hostreplacement.AliasClaimOperation, AdapterID: hostreplacement.AdapterID, TargetID: d.DeclarationID, InputDigest: digest, ArtifactDigest: digest, Idempotent: true}}
	s := &Service{config: Config{AuthorizationBranch: "human", ExecutorMode: "central"}}
	if r, c, e := s.replacementPlan(context.Background(), d, ops); e != nil || r != nil || c == nil {
		t.Fatalf("claim: %v", e)
	}
	for _, name := range []string{"payload", "target", "extension", "operation", "branch", "executor"} {
		t.Run(name, func(t *testing.T) {
			copyD := d
			copyC := claim
			copyD.HostAliasClaim = &copyC
			copyOps := append([]generated.PlanOperation(nil), ops...)
			copyS := *s
			switch name {
			case "payload":
				copyC.HostID = "host-other"
			case "target":
				copyOps[0].TargetID = "other"
			case "extension":
				copyD.Extensions = nil
			case "operation":
				copyOps = append(copyOps, copyOps[0])
			case "branch":
				copyS.config.AuthorizationBranch = "preauthorized"
			case "executor":
				copyS.config.ExecutorMode = "external"
			}
			if _, _, e := copyS.replacementPlan(context.Background(), copyD, copyOps); e == nil {
				t.Fatal("broadened claim accepted")
			}
		})
	}
}
func TestReplacementPlanMissingDraftCannotBecomeOrdinaryOperation(t *testing.T) {
	s := &Service{config: Config{AuthorizationBranch: "human", ExecutorMode: "central"}}
	for _, operation := range []string{hostreplacement.FreezeOperation, hostreplacement.CommitOperation, "host.replacement.unknown"} {
		d := generated.DeclarationRevision{DeclarationType: "host.replacement", Extensions: []generated.ContractExtension{{Name: hostreplacement.ReplacementExtension, ValueDigest: testDigestString("a")}}}
		op := generated.PlanOperation{OperationType: operation, AdapterID: hostreplacement.AdapterID, InputDigest: testDigestString("a"), ArtifactDigest: testDigestString("a"), Idempotent: true}
		if _, _, e := s.replacementPlan(context.Background(), d, []generated.PlanOperation{op}); e == nil {
			t.Fatal("unresolved replacement accepted")
		}
	}
}
func TestReplacementOptionalPlanOmission(t *testing.T) {
	b, e := json.Marshal(generated.Plan{})
	if e != nil || strings.Contains(string(b), "hostReplacement") || strings.Contains(string(b), "hostAliasClaim") || strings.Contains(string(b), "replacementContinuity") {
		t.Fatal("legacy plan changed")
	}
}
