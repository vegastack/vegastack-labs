package server

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/store"
	"testing"
)

func TestNativeCollectorAuthorityRequiresExactOriginalRestore(t *testing.T) {
	scope := generated.QualificationScope{ControllerInstanceID: "prior", Guests: []generated.QualificationGuest{{HostID: "old"}, {HostID: "new"}}}
	b := generated.RestoreBinding{PriorInstanceID: "prior", NewInstanceID: "next", PriorRecoveryEpoch: 0, NextRecoveryEpoch: 1, FormerHostID: "old", ReplacementHostID: "new"}
	s := store.NativeProducerSnapshot{ControllerInstanceID: "next", Revision: store.RevisionToken{RecoveryEpoch: 1}, VerifiedRestoreBinding: &b}
	if !nativeCollectorAuthority(scope, s) {
		t.Fatal("exact verified transition denied")
	}
	for _, name := range []string{"absent", "prior", "current", "epoch", "guest"} {
		t.Run(name, func(t *testing.T) {
			bad := s
			copy := b
			bad.VerifiedRestoreBinding = &copy
			switch name {
			case "absent":
				bad.VerifiedRestoreBinding = nil
			case "prior":
				copy.PriorInstanceID = "other"
			case "current":
				copy.NewInstanceID = "other"
			case "epoch":
				copy.NextRecoveryEpoch = 2
			case "guest":
				copy.ReplacementHostID = "unlaunched"
			}
			if nativeCollectorAuthority(scope, bad) {
				t.Fatal("unbound authority transition accepted")
			}
		})
	}
}
