package plan

import (
	"context"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/hostadoption"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/store"
)

func TestCreateDerivesSealedSingleHostAdoptionRisk(t *testing.T) {
	declaration := validDeclaration()
	declaration.DeclarationType = "host.adoption"
	declaration.Operations = []generated.DeclarationOperation{{Sequence: 1, OperationID: "operation-discovery", OperationType: "host.adopt", AdapterID: "core.host-adoption", TargetID: "target-discovery", InputDigest: testDigestString("a"), ArtifactDigest: testDigestString("a"), Idempotent: true}}
	declaration.Extensions = []generated.ContractExtension{}
	repository := &fakePlanRepository{declaration: declaration, current: store.RevisionToken{StateRevision: 9, RecoveryEpoch: 2}}
	service := newTestService(t, repository, &fakeObservations{fingerprint: testDigestString("b")}, func() time.Time { return time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC) })
	draft := adoptionPlanDraft()
	service.config.HostAdoptions = adoptionPlanReader{draft}
	repository.declaration.Operations[0].InputDigest = draft.Digest
	repository.declaration.Operations[0].ArtifactDigest = draft.Digest
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

func TestCreateRejectsUnsealedOrBroadenedHostAdoptionPlan(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*generated.DeclarationRevision, *Service)
	}{
		{"wrong digest", func(d *generated.DeclarationRevision, _ *Service) {
			d.Operations[0].InputDigest = testDigestString("b")
		}},
		{"extra operation", func(d *generated.DeclarationRevision, _ *Service) {
			other := d.Operations[0]
			other.Sequence, other.OperationID = 2, "operation-extra"
			d.Operations = append(d.Operations, other)
		}},
		{"wrong adapter", func(d *generated.DeclarationRevision, _ *Service) { d.Operations[0].AdapterID = "adapter-test" }},
		{"wrong declaration type", func(d *generated.DeclarationRevision, _ *Service) { d.DeclarationType = "node.configuration" }},
		{"non human branch", func(_ *generated.DeclarationRevision, s *Service) { s.config.AuthorizationBranch = "preauthorized" }},
		{"missing draft reader", func(_ *generated.DeclarationRevision, s *Service) { s.config.HostAdoptions = nil }},
		{"drifted draft", func(_ *generated.DeclarationRevision, s *Service) {
			d := adoptionPlanDraft()
			d.Request.HostID = "different"
			s.config.HostAdoptions = adoptionPlanReader{d}
		}},
		{"external executor", func(_ *generated.DeclarationRevision, s *Service) { s.config.ExecutorMode = "external" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			declaration := validDeclaration()
			declaration.DeclarationType = "host.adoption"
			declaration.Operations = []generated.DeclarationOperation{{Sequence: 1, OperationID: "operation-discovery", OperationType: "host.adopt", AdapterID: "core.host-adoption", TargetID: "target-discovery", InputDigest: testDigestString("a"), ArtifactDigest: testDigestString("a"), Idempotent: true}}
			declaration.Extensions = []generated.ContractExtension{}
			repository := &fakePlanRepository{declaration: declaration, current: store.RevisionToken{StateRevision: 9, RecoveryEpoch: 2}}
			service := newTestService(t, repository, &fakeObservations{fingerprint: testDigestString("b")}, func() time.Time { return time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC) })
			draft := adoptionPlanDraft()
			service.config.HostAdoptions = adoptionPlanReader{draft}
			repository.declaration.Operations[0].InputDigest = draft.Digest
			repository.declaration.Operations[0].ArtifactDigest = draft.Digest
			test.mutate(&repository.declaration, service)
			request := validRequest()
			request.Extensions = repository.declaration.Extensions
			if _, err := service.Create(context.Background(), AuthorScope{PrincipalID: "principal-test", PrincipalMethod: "local-os-peer"}, request); err == nil || repository.committed.Plan.PlanID != "" {
				t.Fatal("unsealed or broadened credential lifecycle plan committed")
			}
		})
	}
}

type adoptionPlanReader struct{ draft store.HostAdoptionDraft }

func (r adoptionPlanReader) GetDraft(context.Context, string) (store.HostAdoptionDraft, error) {
	return r.draft, nil
}
func adoptionPlanDraft() store.HostAdoptionDraft {
	r := generated.HostAdoptionRequest{Schema: generated.SchemaIDHostAdoptionRequest, SchemaVersion: "1.0.0", HostID: "synthetic-host", ObservationID: "observation", ObservationDigest: testDigestString("a"), IdempotencyKey: "registration", ExpectedStateRevision: 9, RecoveryEpoch: 2, Confirmation: generated.HostIdentityConfirmation{Schema: generated.SchemaIDHostIdentityConfirmation, SchemaVersion: "1.0.0", TargetRevision: 1, TargetDigest: testDigestString("b"), IdentityDigest: testDigestString("c"), IdentityClass: "physical", IdentityKind: "product-serial", ConfirmedAt: "2026-09-21T12:00:00Z"}}
	return store.HostAdoptionDraft{ID: "target-discovery", Digest: hostadoption.Digest(r), Request: r}
}
func TestHostAdoptionAbsentPreservesPlanJSON(t *testing.T) {
	p := generated.Plan{}
	raw, err := json.Marshal(p)
	if err != nil || strings.Contains(string(raw), "hostAdoption") {
		t.Fatal("optional addition changed ordinary plans")
	}
}
