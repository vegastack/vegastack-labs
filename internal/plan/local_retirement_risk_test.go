package plan

import (
	"context"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/store"
)

func TestCreateSealsLocalRetentionPlansToOneHumanCentralOperation(t *testing.T) {
	for _, fixture := range []struct {
		declarationType, operationType, adapterID, extension string
	}{
		{"backup.retention-locks", "backup.retention-locks.activate", "core.retention-locks", "x-backup-retention-lock-catalog"},
		{"backup.retirement", "backup.local.retire", "local.retention", "x-backup-local-retirement"},
	} {
		t.Run(fixture.operationType, func(t *testing.T) {
			declaration := validDeclaration()
			declaration.DeclarationType = fixture.declarationType
			declaration.Operations = []generated.DeclarationOperation{{Sequence: 1, OperationID: "operation-retention", OperationType: fixture.operationType, AdapterID: fixture.adapterID, TargetID: "repository-standard", InputDigest: testDigestString("a"), ArtifactDigest: testDigestString("b"), Idempotent: false}}
			declaration.Extensions = []generated.ContractExtension{{Name: fixture.extension, ValueDigest: testDigestString("c")}}
			repository := &fakePlanRepository{declaration: declaration, current: store.RevisionToken{StateRevision: 9, RecoveryEpoch: 2}}
			service := newTestService(t, repository, &fakeObservations{fingerprint: testDigestString("b")}, func() time.Time { return time.Date(2026, 9, 23, 8, 0, 0, 0, time.UTC) })
			request := validRequest()
			request.Extensions = declaration.Extensions
			created, err := service.Create(context.Background(), AuthorScope{PrincipalID: "principal-test", PrincipalMethod: "local-os-peer"}, request)
			if err != nil {
				t.Fatal(err)
			}
			if created.Plan.Risk != string(authorization.RiskDestructive) || created.Plan.AuthorizationBranch != "human" || created.Plan.ExecutorMode != "central" {
				t.Fatalf("retention plan policy = %q/%q/%q", created.Plan.Risk, created.Plan.AuthorizationBranch, created.Plan.ExecutorMode)
			}

			for _, mutate := range []func(*generated.DeclarationRevision, *Service){
				func(d *generated.DeclarationRevision, _ *Service) { d.Extensions = nil },
				func(d *generated.DeclarationRevision, _ *Service) { d.Operations[0].AdapterID = "adapter-test" },
				func(d *generated.DeclarationRevision, _ *Service) { d.Operations[0].Idempotent = true },
				func(d *generated.DeclarationRevision, _ *Service) {
					other := d.Operations[0]
					other.Sequence = 2
					other.OperationID = "operation-extra"
					d.Operations = append(d.Operations, other)
				},
				func(_ *generated.DeclarationRevision, s *Service) { s.config.AuthorizationBranch = "preauthorized" },
				func(_ *generated.DeclarationRevision, s *Service) { s.config.ExecutorMode = "external" },
			} {
				copyDeclaration := declaration
				copyDeclaration.Operations = append([]generated.DeclarationOperation(nil), declaration.Operations...)
				copyDeclaration.Extensions = append([]generated.ContractExtension(nil), declaration.Extensions...)
				badRepository := &fakePlanRepository{declaration: copyDeclaration, current: store.RevisionToken{StateRevision: 9, RecoveryEpoch: 2}}
				badService := newTestService(t, badRepository, &fakeObservations{fingerprint: testDigestString("b")}, func() time.Time { return time.Date(2026, 9, 23, 8, 0, 0, 0, time.UTC) })
				mutate(&badRepository.declaration, badService)
				badRequest := validRequest()
				badRequest.Extensions = badRepository.declaration.Extensions
				if _, err := badService.Create(context.Background(), AuthorScope{PrincipalID: "principal-test", PrincipalMethod: "local-os-peer"}, badRequest); err == nil {
					t.Fatal("unsealed or broadened retention plan committed")
				}
			}
		})
	}
}
