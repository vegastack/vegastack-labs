package change

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/hostreplacement"
	"testing"
)

func aliasClaimRequest() generated.DeclarationRevisionRequest {
	c := generated.HostAliasClaimRequest{Schema: generated.SchemaIDHostAliasClaimRequest, SchemaVersion: "1.0.0", HostID: "host-a", HostIdentityDigest: testDigestString("a"), AliasIDs: []string{"alias-a"}, ExpectedStateRevision: 4, RecoveryEpoch: 2, IdempotencyKey: "claim-a"}
	d := hostaction.Digest(c)
	return generated.DeclarationRevisionRequest{Schema: generated.SchemaIDDeclarationRevisionRequest, SchemaVersion: "1.0.0", DeclarationID: "claim-a", DeclarationType: "host.alias-claim", ExpectedRevision: 1, ExpectedStateRevision: 4, RecoveryEpoch: 2, HostAliasClaim: &c, ReasonDigest: d, Extensions: []generated.ContractExtension{{Name: hostreplacement.AliasClaimExtension, ValueDigest: d}}, Operations: []generated.DeclarationOperation{{Sequence: 1, OperationID: "claim", OperationType: hostreplacement.AliasClaimOperation, AdapterID: hostreplacement.AdapterID, TargetID: "claim-a", InputDigest: d, ArtifactDigest: d, Idempotent: true}}}
}
func TestAliasClaimDeclarationRequiresExactTypedPayload(t *testing.T) {
	cases := map[string]func(*generated.DeclarationRevisionRequest){"digest-only": func(r *generated.DeclarationRevisionRequest) { r.HostAliasClaim = nil }, "missing-extension": func(r *generated.DeclarationRevisionRequest) { r.Extensions = nil }, "mixed": func(r *generated.DeclarationRevisionRequest) {
		r.Operations = append(r.Operations, r.Operations[0])
		r.Operations[1].Sequence = 2
	}, "stale-epoch": func(r *generated.DeclarationRevisionRequest) { r.HostAliasClaim.RecoveryEpoch++ }, "stale-revision": func(r *generated.DeclarationRevisionRequest) { r.HostAliasClaim.ExpectedStateRevision++ }, "wrong-target": func(r *generated.DeclarationRevisionRequest) { r.Operations[0].TargetID = "another" }, "changed-payload": func(r *generated.DeclarationRevisionRequest) { r.HostAliasClaim.HostID = "host-b" }, "wrong-type": func(r *generated.DeclarationRevisionRequest) { r.DeclarationType = "other" }, "mixed-extension": func(r *generated.DeclarationRevisionRequest) {
		r.Extensions = append(r.Extensions, generated.ContractExtension{Name: "x-other", ValueDigest: testDigestString("b")})
	}}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			repo := &fakeRepository{}
			s, _ := NewService(repo, nil)
			r := aliasClaimRequest()
			mutate(&r)
			if _, err := s.Revise(context.Background(), AuthorScope{PrincipalID: "human", PrincipalMethod: "local-os-peer", AgentSessionID: "session"}, r); err == nil {
				t.Fatal("unbound alias claim accepted")
			}
			if repo.request.Document.DeclarationID != "" {
				t.Fatal("invalid request reached repository")
			}
		})
	}
}
func TestAliasClaimPayloadPreservedAndSemanticDigestBound(t *testing.T) {
	repo := &fakeRepository{}
	s, _ := NewService(repo, nil)
	r := aliasClaimRequest()
	author := AuthorScope{PrincipalID: "human", PrincipalMethod: "local-os-peer", AgentSessionID: "session"}
	first, err := s.Revise(context.Background(), author, r)
	if err != nil {
		t.Fatal(err)
	}
	if first.Document.HostAliasClaim == nil || first.Document.HostAliasClaim.HostID != "host-a" {
		t.Fatal("payload lost")
	}
	r.HostAliasClaim.HostID = "host-b"
	d := hostaction.Digest(r.HostAliasClaim)
	r.Operations[0].InputDigest = d
	r.Operations[0].ArtifactDigest = d
	r.Extensions[0].ValueDigest = d
	r.ReasonDigest = d
	second, err := s.Revise(context.Background(), author, r)
	if err != nil {
		t.Fatal(err)
	}
	if first.Document.ContentDigest == second.Document.ContentDigest {
		t.Fatal("semantic digest omitted payload")
	}
	if first.Document.HostAliasClaim.HostID != "host-a" {
		t.Fatal("document aliased mutable request")
	}
}
