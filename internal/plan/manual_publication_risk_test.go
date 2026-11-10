package plan

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/store"
	"testing"
	"time"
)

func manualPublicationRiskFixture(t *testing.T) (*fakePlanRepository, *Service) {
	t.Helper()
	d := validDeclaration()
	d.DeclarationType = store.ManualPublicationOperation
	d.Operations = []generated.DeclarationOperation{{Sequence: 1, OperationID: "manual-publication", OperationType: store.ManualPublicationOperation, AdapterID: store.ManualPublicationAdapter, TargetID: "synthetic-image", InputDigest: testDigestString("a"), ArtifactDigest: testDigestString("b"), Idempotent: false}}
	d.Extensions = []generated.ContractExtension{{Name: store.ManualPublicationExtension, ValueDigest: testDigestString("b")}, {Name: "x-credential-bindings", ValueDigest: testDigestString("a")}}
	repository := &fakePlanRepository{declaration: d, current: store.RevisionToken{StateRevision: 9, RecoveryEpoch: 2}}
	service := newTestService(t, repository, &fakeObservations{fingerprint: testDigestString("b")}, func() time.Time { return time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC) })
	service.config.Risk = "destructive"
	return repository, service
}

func TestCreateManualPublicationRiskFromProductionDefault(t *testing.T) {
	repository, service := manualPublicationRiskFixture(t)
	request := validRequest()
	request.Extensions = repository.declaration.Extensions
	created, e := service.Create(context.Background(), AuthorScope{PrincipalID: "principal-test", PrincipalMethod: "local-os-peer"}, request)
	if e != nil {
		t.Fatal(e)
	}
	if created.Plan.Risk != string(authorization.RiskControlPlane) {
		t.Fatalf("production-default manual publication risk = %q; want control-plane", created.Plan.Risk)
	}
	if risk, e := authorization.ClassifyPlan(created.Plan); e != nil || risk != authorization.RiskControlPlane {
		t.Fatalf("actual plan cannot enter human approval: %q, %v", risk, e)
	}
	if repository.committed.Plan.PlanID == "" {
		t.Fatal("plan not committed")
	}
}

func TestCreateRejectsBroadenedManualPublication(t *testing.T) {
	cases := map[string]func(*generated.DeclarationRevision, *Service){
		"wrong-declaration": func(d *generated.DeclarationRevision, s *Service) { d.DeclarationType = "node.configuration" },
		"wrong-adapter":     func(d *generated.DeclarationRevision, s *Service) { d.Operations[0].AdapterID = "adapter-other" },
		"wrong-operation": func(d *generated.DeclarationRevision, s *Service) {
			d.Operations[0].OperationType = "configuration.update"
		},
		"idempotent": func(d *generated.DeclarationRevision, s *Service) { d.Operations[0].Idempotent = true },
		"wrong-extension-digest": func(d *generated.DeclarationRevision, s *Service) {
			d.Extensions[0].ValueDigest = testDigestString("c")
		},
		"mixed-payload": func(d *generated.DeclarationRevision, s *Service) {
			d.HostingLifecycle = &generated.HostingLifecycleRequest{}
		},
		"extra-operation": func(d *generated.DeclarationRevision, s *Service) {
			o := d.Operations[0]
			o.Sequence = 2
			o.OperationID = "other"
			d.Operations = append(d.Operations, o)
		},
		"nonhuman":   func(d *generated.DeclarationRevision, s *Service) { s.config.AuthorizationBranch = "preauthorized" },
		"noncentral": func(d *generated.DeclarationRevision, s *Service) { s.config.ExecutorMode = "external" },
	}
	for name, modify := range cases {
		t.Run(name, func(t *testing.T) {
			repository, service := manualPublicationRiskFixture(t)
			modify(&repository.declaration, service)
			request := validRequest()
			request.Extensions = repository.declaration.Extensions
			_, e := service.Create(context.Background(), AuthorScope{PrincipalID: "principal-test", PrincipalMethod: "local-os-peer"}, request)
			if e == nil || repository.committed.Plan.PlanID != "" {
				t.Fatal("broadened manual publication committed")
			}
		})
	}
}
