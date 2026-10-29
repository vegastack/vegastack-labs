package plan

import (
	"context"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/store"
)

func TestCreateControllerSetupRiskFromProductionDefault(t *testing.T) {
	repository, service := controllerSetupPlanFixture(t)
	created, err := service.Create(context.Background(), AuthorScope{PrincipalID: "principal-test", PrincipalMethod: "local-os-peer"}, validRequest())
	if err != nil {
		t.Fatal(err)
	}
	if created.Plan.Risk != "control-plane" {
		t.Fatalf("production-default controller plan risk = %q; want control-plane", created.Plan.Risk)
	}
	if risk, err := authorization.ClassifyPlan(created.Plan); err != nil || risk != authorization.RiskControlPlane {
		t.Fatalf("classification agreement: %q, %v", risk, err)
	}
	if repository.committed.Plan.PlanID == "" {
		t.Fatal("plan not committed")
	}
}

func TestCreateRejectsBroadenedControllerSetup(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*generated.DeclarationRevision, *Service)
	}{
		{"wrong adapter", func(d *generated.DeclarationRevision, _ *Service) { d.Operations[0].AdapterID = "adapter-test" }},
		{"wrong operation", func(d *generated.DeclarationRevision, _ *Service) {
			d.Operations[0].OperationType = "controller.setup.other"
		}},
		{"wrong declaration", func(d *generated.DeclarationRevision, _ *Service) { d.DeclarationType = "node.configuration" }},
		{"extra operation", func(d *generated.DeclarationRevision, _ *Service) {
			op := d.Operations[0]
			op.Sequence = 2
			op.OperationID = "other"
			d.Operations = append(d.Operations, op)
		}},
		{"idempotent", func(d *generated.DeclarationRevision, _ *Service) { d.Operations[0].Idempotent = true }},
		{"bad input digest", func(d *generated.DeclarationRevision, _ *Service) { d.Operations[0].InputDigest = "invalid" }},
		{"bad artifact digest", func(d *generated.DeclarationRevision, _ *Service) { d.Operations[0].ArtifactDigest = "invalid" }},
		{"offsite payload", func(d *generated.DeclarationRevision, _ *Service) {
			d.Operations[0].OffsiteRunSpec = &generated.OffsiteRunSpec{}
		}},
		{"hosting payload", func(d *generated.DeclarationRevision, _ *Service) {
			d.HostingLifecycle = &generated.HostingLifecycleRequest{}
		}},
		{"recovery payload", func(d *generated.DeclarationRevision, _ *Service) {
			d.ServiceRecovery = &generated.ServiceRecoveryRequest{}
		}},
		{"deployment payload", func(d *generated.DeclarationRevision, _ *Service) {
			d.ServiceDeployment = &generated.ServiceDeploymentRequest{}
		}},
		{"ci job payload", func(d *generated.DeclarationRevision, _ *Service) { d.CIJob = &generated.CiJobRequest{} }},
		{"ci enrollment payload", func(d *generated.DeclarationRevision, _ *Service) { d.CIEnrollment = &generated.CiEnrollmentRequest{} }},
		{"import payload", func(d *generated.DeclarationRevision, _ *Service) {
			d.ServiceImport = &generated.ServiceImportRequest{}
		}},
		{"network payload", func(d *generated.DeclarationRevision, _ *Service) {
			d.NetworkEndpoint = &generated.NetworkEndpointRequest{}
		}},
		{"grant payload", func(d *generated.DeclarationRevision, _ *Service) {
			d.AuthorizationGrantBatch = &generated.AuthorizationGrantBatchRequest{}
		}},
		{"alias payload", func(d *generated.DeclarationRevision, _ *Service) {
			d.HostAliasClaim = &generated.HostAliasClaimRequest{}
		}},
		{"mixed payload", func(d *generated.DeclarationRevision, _ *Service) { d.Maintenance = &generated.MaintenanceRecord{} }},
		{"extension", func(d *generated.DeclarationRevision, _ *Service) {
			d.Extensions = []generated.ContractExtension{{Name: "x-other", ValueDigest: testDigestString("a")}}
		}},
		{"non human", func(_ *generated.DeclarationRevision, s *Service) { s.config.AuthorizationBranch = "preauthorized" }},
		{"external", func(_ *generated.DeclarationRevision, s *Service) { s.config.ExecutorMode = "external" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repository, service := controllerSetupPlanFixture(t)
			tc.mutate(&repository.declaration, service)
			request := validRequest()
			request.Extensions = repository.declaration.Extensions
			if _, err := service.Create(context.Background(), AuthorScope{PrincipalID: "principal-test", PrincipalMethod: "local-os-peer"}, request); err == nil || repository.committed.Plan.PlanID != "" {
				t.Fatal("broadened controller setup committed")
			}
		})
	}
}

func controllerSetupPlanFixture(t *testing.T) (*fakePlanRepository, *Service) {
	t.Helper()
	d := validDeclaration()
	d.DeclarationType = "controller.setup"
	d.Operations = []generated.DeclarationOperation{{Sequence: 1, OperationID: "foundation", OperationType: "controller.setup.bootstrap", AdapterID: "core.controller-setup", TargetID: "synthetic-controller", InputDigest: testDigestString("a"), ArtifactDigest: testDigestString("b")}}
	repository := &fakePlanRepository{declaration: d, current: store.RevisionToken{StateRevision: 9, RecoveryEpoch: 2}}
	service := newTestService(t, repository, &fakeObservations{fingerprint: testDigestString("b")}, func() time.Time { return time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC) })
	service.config.Risk = "destructive"
	return repository, service
}
