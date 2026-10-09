//go:build linux

package qualification

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
	"testing"
)

func TestNativePreparationLookupAndFixtureApprovalStayFinite(t *testing.T) {
	scope, err := validateScope(scopeFixture())
	if err != nil {
		t.Fatal(err)
	}
	binding := generated.NativeStepRequest{Operation: "prepare", GuestID: "subject", ScenarioID: "baseline-access", RecoveryEpoch: 0}
	lookup := generated.NativePreparationRequest{Binding: binding, Kind: "producer-lookup", ProducerLookup: &generated.NativeProducerLookupRequest{ScopeDigest: scope.digest, ScenarioID: binding.ScenarioID, HostID: scope.guests["subject"].HostID}}
	if validatePreparation(scope, lookup) != nil {
		t.Fatal("lookup rejected")
	}
	for _, variant := range []string{"host", "scope", "scenario", "epoch", "mixed"} {
		t.Run(variant, func(t *testing.T) {
			bad := lookup
			v := *lookup.ProducerLookup
			bad.ProducerLookup = &v
			switch variant {
			case "host":
				v.HostID = "outside"
			case "scope":
				v.ScopeDigest = "other"
			case "scenario":
				v.ScenarioID = "role-ci"
			case "epoch":
				v.RecoveryEpoch = 1
			case "mixed":
				bad.Identifier = "caller-path"
			}
			if validatePreparation(scope, bad) == nil {
				t.Fatal("lookup escaped binding")
			}
		})
	}
	approval := generated.NativePreparationRequest{Binding: binding, Kind: "fixture-approval", FixtureApproval: &generated.NativeSlackFixtureApproval{RecoveryEpoch: 0}}
	if validatePreparation(scope, approval) != nil {
		t.Fatal("approval rejected")
	}
	approval.Identifier = "caller-human"
	if validatePreparation(scope, approval) == nil {
		t.Fatal("extra authority accepted")
	}
}

func TestPreparationCannotMixRequestsOrChangeScopedHost(t *testing.T) {
	scope, err := validateScope(scopeFixture())
	if err != nil {
		t.Fatal(err)
	}
	in := generated.NativePreparationRequest{Schema: generated.SchemaIDNativePreparationRequest, SchemaVersion: "1.0.0", Binding: generated.NativeStepRequest{Operation: "prepare", GuestID: "subject", RecoveryEpoch: 0}, Kind: "action", Action: &generated.HostActionRequest{HostID: scope.guests["subject"].HostID, RecoveryEpoch: 0}}
	if err = validatePreparation(scope, in); err != nil {
		t.Fatal(err)
	}
	for _, variant := range []string{"extra-identifier", "extra-action", "other-host", "other-epoch", "raw-command", "unknown-guest"} {
		t.Run(variant, func(t *testing.T) {
			bad := in
			a := *in.Action
			bad.Action = &a
			switch variant {
			case "extra-identifier":
				bad.Identifier = "another-plan"
			case "extra-action":
				bad.Discovery = &generated.HostDiscoveryRequest{}
			case "other-host":
				bad.Action.HostID = "outside"
			case "other-epoch":
				bad.Action.RecoveryEpoch = 1
			case "raw-command":
				bad.Kind = "shell"
			case "unknown-guest":
				bad.Binding.GuestID = "outside"
			}
			if validatePreparation(scope, bad) == nil {
				t.Fatal("broadened preparation admitted")
			}
		})
	}
}

func TestRecoveryPreparationCannotEscapeScopeOrMixInputs(t *testing.T) {
	scope, err := validateScope(scopeFixture())
	if err != nil {
		t.Fatal(err)
	}
	hosts := []string{}
	for _, g := range scope.guests {
		hosts = append(hosts, g.HostID)
	}
	in := generated.NativePreparationRequest{Binding: generated.NativeStepRequest{Operation: "prepare", GuestID: "subject", RecoveryEpoch: 0}, Kind: "restore-plan", RestorePlan: &generated.RestoreRequest{RecoveryEpoch: 0, FormerHostID: hosts[0], ReplacementHostID: hosts[1]}}
	if validatePreparation(scope, in) != nil {
		t.Fatal("scoped restore rejected")
	}
	for _, variant := range []string{"outside", "same-host", "epoch", "mixed"} {
		t.Run(variant, func(t *testing.T) {
			bad := in
			q := *in.RestorePlan
			bad.RestorePlan = &q
			switch variant {
			case "outside":
				q.ReplacementHostID = "outside"
			case "same-host":
				q.ReplacementHostID = q.FormerHostID
			case "epoch":
				q.RecoveryEpoch = 1
			case "mixed":
				bad.BackupRun = &generated.BackupRunRequest{}
			}
			if validatePreparation(scope, bad) == nil {
				t.Fatal("broadened restore accepted")
			}
		})
	}
	for _, kind := range []string{"backup-policy", "backup-run", "backup-verify", "restore-run", "restore-verify"} {
		bad := in
		bad.Kind = kind
		if validatePreparation(scope, bad) == nil {
			t.Fatal("missing/mixed payload accepted", kind)
		}
	}
}
