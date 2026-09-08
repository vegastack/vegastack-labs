package identity

import (
	"context"
	"testing"
)

func TestResolverUsesOnlyExactUIDBinding(t *testing.T) {
	resolver, err := NewLocalPrincipalResolver([]Binding{{UID: 1001, PrincipalID: "principal.operator"}})
	if err != nil {
		t.Fatal(err)
	}
	principal, err := resolver.ResolveLocalPeer(context.Background(), LocalPeer{PID: 77, UID: 1001, GID: 9999})
	if err != nil || principal.ID != "principal.operator" || principal.Method != "local-os-peer" {
		t.Fatalf("ResolveLocalPeer() = (%#v, %v)", principal, err)
	}
	if _, err := resolver.ResolveLocalPeer(context.Background(), LocalPeer{PID: 77, UID: 1002, GID: 1001}); err == nil {
		t.Fatal("same-number GID authenticated an unmapped UID")
	}
}

func TestResolverRejectsInvalidOrAmbiguousBindings(t *testing.T) {
	tests := [][]Binding{
		nil,
		{{UID: 1, PrincipalID: "UPPER"}},
		{{UID: 1, PrincipalID: "principal.one"}, {UID: 1, PrincipalID: "principal.two"}},
		{{UID: 1, PrincipalID: "principal.one"}, {UID: 2, PrincipalID: "principal.one"}},
	}
	for _, bindings := range tests {
		if _, err := NewLocalPrincipalResolver(bindings); err == nil {
			t.Fatalf("NewLocalPrincipalResolver(%#v) error = nil", bindings)
		}
	}
}

func TestResolverCopiesBindingsAndHonorsCancellation(t *testing.T) {
	bindings := []Binding{{UID: 42, PrincipalID: "principal.original"}}
	resolver, err := NewLocalPrincipalResolver(bindings)
	if err != nil {
		t.Fatal(err)
	}
	bindings[0].PrincipalID = "principal.changed"
	principal, err := resolver.ResolveLocalPeer(context.Background(), LocalPeer{UID: 42})
	if err != nil || principal.ID != "principal.original" {
		t.Fatalf("ResolveLocalPeer() = (%#v, %v)", principal, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := resolver.ResolveLocalPeer(ctx, LocalPeer{UID: 42}); err == nil {
		t.Fatal("cancelled resolution succeeded")
	}
}

func TestVerifiedPrincipalContext(t *testing.T) {
	principal := Principal{ID: "principal.operator", Method: "local-os-peer"}
	ctx := WithVerifiedPrincipal(context.Background(), principal)
	got, ok := PrincipalFromContext(ctx)
	if !ok || got != principal {
		t.Fatalf("PrincipalFromContext() = (%#v, %t)", got, ok)
	}
	if _, ok := PrincipalFromContext(context.Background()); ok {
		t.Fatal("empty context contained a principal")
	}
}
