package server

import (
	"context"
	"errors"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/ingressconnector"
	ingress "github.com/vegastack/vegastack-labs/internal/networkingress"
	"strings"
	"testing"
)

func TestControllerConnectorBindsExactFreshTunnelSelection(t *testing.T) {
	d := hostaction.Digest("identity")
	m := hostaction.Digest("policy")
	selected := connectorSelection{HostID: "controller-a", IdentityDigest: d, AccountID: strings.Repeat("a", 32), TunnelID: "11111111-1111-4111-8111-111111111111"}
	for _, variant := range []string{"exact", "host", "identity", "account", "tunnel", "marker", "ca-pool", "unselected-ca"} {
		t.Run(variant, func(t *testing.T) {
			c := ingressconnector.Input{HostID: selected.HostID, HostIdentityDigest: d, AccountID: selected.AccountID, TunnelID: selected.TunnelID, ControllerSetupPilotDigest: m}
			s := selected
			switch variant {
			case "host":
				c.HostID = "another-host"
			case "identity":
				c.HostIdentityDigest = hostaction.Digest("other")
			case "account":
				c.AccountID = strings.Repeat("b", 32)
			case "tunnel":
				c.TunnelID = "22222222-2222-4222-8222-222222222222"
			case "marker":
				c.ControllerSetupPilotDigest = hostaction.Digest("other")
			case "ca-pool":
				s.OriginCAPool = ingressconnector.CAPath
			case "unselected-ca":
				c.OriginCADigest = hostaction.Digest("CA")
			}
			if e := matchControllerConnector(c, s, m); (e == nil) != (variant == "exact") {
				t.Fatal(variant, e)
			}
		})
	}
}

type controllerNativeRefs map[string]generated.CredentialReference

func (r controllerNativeRefs) GetActiveVersion(_ context.Context, id string, _ int64) (generated.CredentialReference, error) {
	v, ok := r[id]
	if !ok {
		return v, errors.New("missing")
	}
	return v, nil
}
func TestControllerConnectorRequiresBothCurrentNativePurposesAndDeniedObservation(t *testing.T) {
	for _, variant := range []string{"exact", "missing", "wrong-purpose", "fallback", "stale-epoch", "unverified", "native-denied-check-fails"} {
		t.Run(variant, func(t *testing.T) {
			activated := "2026-10-28T00:00:00Z"
			c := generated.IngressChange{ProfileID: "profile-a", ObservationReferenceID: "observe-a", MutationReferenceID: "mutate-a"}
			p := generated.Plan{Binding: generated.PlanBinding{StateRevision: 4, RecoveryEpoch: 2}, Operations: []generated.PlanOperation{{OperationID: "connector"}}}
			refs := controllerNativeRefs{}
			for _, v := range []struct{ id, purpose string }{{"observe-a", ingress.PurposeRead}, {"mutate-a", ingress.PurposeWrite}} {
				refs[v.id] = generated.CredentialReference{ReferenceID: v.id, ConsumerID: ingress.AdapterID, PurposeID: v.purpose, TargetID: c.ProfileID, ResolverID: "native-systemd", MaterialVersion: "one", Status: "active", StateRevision: 3, RecoveryEpoch: 2, ActivatedAt: &activated, VerifiedConsumerIDs: []string{ingress.AdapterID}}
			}
			v := refs["mutate-a"]
			switch variant {
			case "missing":
				delete(refs, "mutate-a")
			case "wrong-purpose":
				v.PurposeID = ingress.PurposeRead
			case "fallback":
				v.ResolverID = "workstation"
			case "stale-epoch":
				v.RecoveryEpoch = 1
			case "unverified":
				v.VerifiedConsumerIDs = nil
			}
			if variant != "missing" {
				refs["mutate-a"] = v
			}
			observed := 0
			e := checkControllerConnectorNative(context.Background(), p, c, refs, func(context.Context, credentialref.StepBinding) error {
				observed++
				if variant == "native-denied-check-fails" {
					return errors.New("denied-reader opened")
				}
				return nil
			})
			if (e == nil) != (variant == "exact") {
				t.Fatal(variant, e)
			}
			if variant == "exact" && observed != 2 {
				t.Fatal("both native purposes not observed")
			}
		})
	}
}
