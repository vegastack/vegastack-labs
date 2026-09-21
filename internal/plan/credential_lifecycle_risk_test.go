package plan

import (
	"context"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/store"
)

func TestCreateDerivesSealedSingleCredentialLifecycleRisk(t *testing.T) {
	declaration := validDeclaration()
	declaration.DeclarationType = "credential.lifecycle"
	declaration.Operations = []generated.DeclarationOperation{{Sequence: 1, OperationID: "operation-credential", OperationType: "credential.stage", AdapterID: "core.credential", TargetID: "target-credential", InputDigest: testDigestString("a"), ArtifactDigest: testDigestString("a"), Idempotent: true}}
	declaration.Extensions = []generated.ContractExtension{{Name: "x-credential-lifecycle", ValueDigest: testDigestString("b")}}
	repository := &fakePlanRepository{declaration: declaration, current: store.RevisionToken{StateRevision: 9, RecoveryEpoch: 2}}
	service := newTestService(t, repository, &fakeObservations{fingerprint: testDigestString("b")}, func() time.Time { return time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC) })
	request := validRequest()
	request.Extensions = declaration.Extensions
	created, err := service.Create(context.Background(), AuthorScope{PrincipalID: "principal-test", PrincipalMethod: "local-os-peer"}, request)
	if err != nil {
		t.Fatal(err)
	}
	if created.Plan.Risk != string(authorization.RiskControlPlane) || created.Plan.AuthorizationBranch != "human" || created.Plan.ExecutorMode != "central" {
		t.Fatalf("lifecycle plan policy = %q/%q/%q", created.Plan.Risk, created.Plan.AuthorizationBranch, created.Plan.ExecutorMode)
	}
	if risk, err := authorization.ClassifyPlan(created.Plan); err != nil || risk != authorization.RiskControlPlane {
		t.Fatalf("lifecycle plan classification = %q, %v", risk, err)
	}
}

func TestCreateRejectsUnsealedOrBroadenedCredentialLifecyclePlan(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*generated.DeclarationRevision, *Service)
	}{
		{"missing seal", func(d *generated.DeclarationRevision, _ *Service) { d.Extensions = nil }},
		{"extra operation", func(d *generated.DeclarationRevision, _ *Service) {
			other := d.Operations[0]
			other.Sequence, other.OperationID = 2, "operation-extra"
			d.Operations = append(d.Operations, other)
		}},
		{"wrong adapter", func(d *generated.DeclarationRevision, _ *Service) { d.Operations[0].AdapterID = "adapter-test" }},
		{"wrong declaration type", func(d *generated.DeclarationRevision, _ *Service) { d.DeclarationType = "node.configuration" }},
		{"non human branch", func(_ *generated.DeclarationRevision, s *Service) { s.config.AuthorizationBranch = "preauthorized" }},
		{"external executor", func(_ *generated.DeclarationRevision, s *Service) { s.config.ExecutorMode = "external" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			declaration := validDeclaration()
			declaration.DeclarationType = "credential.lifecycle"
			declaration.Operations = []generated.DeclarationOperation{{Sequence: 1, OperationID: "operation-credential", OperationType: "credential.stage", AdapterID: "core.credential", TargetID: "target-credential", InputDigest: testDigestString("a"), ArtifactDigest: testDigestString("a"), Idempotent: false}}
			declaration.Extensions = []generated.ContractExtension{{Name: "x-credential-lifecycle", ValueDigest: testDigestString("b")}}
			repository := &fakePlanRepository{declaration: declaration, current: store.RevisionToken{StateRevision: 9, RecoveryEpoch: 2}}
			service := newTestService(t, repository, &fakeObservations{fingerprint: testDigestString("b")}, func() time.Time { return time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC) })
			test.mutate(&repository.declaration, service)
			request := validRequest()
			request.Extensions = repository.declaration.Extensions
			if _, err := service.Create(context.Background(), AuthorScope{PrincipalID: "principal-test", PrincipalMethod: "local-os-peer"}, request); err == nil || repository.committed.Plan.PlanID != "" {
				t.Fatal("unsealed or broadened credential lifecycle plan committed")
			}
		})
	}
}
