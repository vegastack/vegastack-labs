package plan

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"github.com/vegastack/vegastack-labs/internal/hostdiscovery"
	"golang.org/x/crypto/ssh"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/store"
)

func TestCreateDerivesSealedSingleDiscoveryTargetRisk(t *testing.T) {
	declaration := validDeclaration()
	declaration.DeclarationType = "host.discovery-target"
	declaration.Operations = []generated.DeclarationOperation{{Sequence: 1, OperationID: "operation-discovery", OperationType: "host.discovery-target.activate", AdapterID: "core.host-discovery-target", TargetID: "target-discovery", InputDigest: testDigestString("a"), ArtifactDigest: testDigestString("a"), Idempotent: true}}
	declaration.Extensions = []generated.ContractExtension{}
	repository := &fakePlanRepository{declaration: declaration, current: store.RevisionToken{StateRevision: 9, RecoveryEpoch: 2}}
	service := newTestService(t, repository, &fakeObservations{fingerprint: testDigestString("b")}, func() time.Time { return time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC) })
	draft := discoveryPlanDraft(t)
	service.config.HostDiscoveryTargets = discoveryPlanReader{draft}
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

func TestCreateRejectsUnsealedOrBroadenedDiscoveryTargetPlan(t *testing.T) {
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
		{"external executor", func(_ *generated.DeclarationRevision, s *Service) { s.config.ExecutorMode = "external" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			declaration := validDeclaration()
			declaration.DeclarationType = "host.discovery-target"
			declaration.Operations = []generated.DeclarationOperation{{Sequence: 1, OperationID: "operation-discovery", OperationType: "host.discovery-target.activate", AdapterID: "core.host-discovery-target", TargetID: "target-discovery", InputDigest: testDigestString("a"), ArtifactDigest: testDigestString("a"), Idempotent: false}}
			declaration.Extensions = []generated.ContractExtension{}
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

type discoveryPlanReader struct{ draft store.DiscoveryDraft }

func (r discoveryPlanReader) GetDraft(context.Context, string) (store.DiscoveryDraft, error) {
	return r.draft, nil
}
func discoveryPlanDraft(t *testing.T) store.DiscoveryDraft {
	_, private, _ := ed25519.GenerateKey(rand.Reader)
	key, _ := ssh.NewSignerFromKey(private)
	target := generated.HostDiscoveryTarget{Schema: generated.SchemaIDHostDiscoveryTarget, SchemaVersion: "1.0.0", TargetID: "synthetic", Revision: 1, Address: "127.0.0.1", Port: 2222, User: "inspect", HostKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key.PublicKey()))), ProfileID: "profile-a", CredentialReferenceID: "key-a", MaterialVersion: "v1", ExpectedOS: "debian", ExpectedVersion: "13", ExpectedArchitecture: "amd64"}
	r := generated.HostDiscoveryTargetDraftRequest{Schema: generated.SchemaIDHostDiscoveryTargetDraftRequest, SchemaVersion: "1.0.0", Target: target, Action: "activate", IdempotencyKey: "fixture"}
	return store.DiscoveryDraft{ID: "target-discovery", Digest: hostdiscovery.Digest(r), Request: r}
}
