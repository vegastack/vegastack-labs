package server

import (
	"context"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/store"
)

func TestHostActionTargetUsesDeclaredActionUser(t *testing.T) {
	for _, tc := range []struct{ name, actionUser, want string }{
		{"dedicated helper", "automation", "automation"},
		{"legacy target", "", "inspect"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			identity := "sha256:" + strings.Repeat("a", 64)
			target := generated.HostDiscoveryTarget{TargetID: "target-a", Revision: 7, Address: "127.0.0.1", Port: 22, User: "inspect", HostKey: "pinned-key"}
			if tc.actionUser != "" {
				target.ActionUser = new(tc.actionUser)
			}
			request := generated.HostActionRequest{HostID: "host-a", TargetRevision: 7, AutomationPrincipalID: "automation-a", CallerUID: 1002, ConsoleConfirmation: generated.HostActionConsoleConfirmation{HostIdentityDigest: identity}}
			source := &actionTestSource{x: store.HostActionExecution{Target: target, Draft: store.HostActionDraft{Request: request}}}
			resolver := hostActionTargets{repository: source, allowed: []string{identity}}
			bundle := generated.HostActionBundle{HostID: "host-a", HostIdentityDigest: identity, CallerUID: 1002, AutomationPrincipalID: "automation-a"}
			got, err := resolver.Resolve(context.Background(), bundle)
			if err != nil {
				t.Fatal(err)
			}
			if got.User != tc.want {
				t.Fatalf("action SSH user = %q, want %q; discovery account must stay separate", got.User, tc.want)
			}
			if target.User != "inspect" || source.x.Target.User != "inspect" {
				t.Fatal("discovery login changed")
			}
			if got.Address != target.Address || got.Port != 22 || got.HostKey != target.HostKey || got.HostID != request.HostID || got.HostIdentityDigest != identity || got.CallerUID != 1002 || got.Revision != 7 || got.AutomationPrincipalID != request.AutomationPrincipalID {
				t.Fatalf("action-user selection changed another transport binding: %+v", got)
			}
		})
	}
}
