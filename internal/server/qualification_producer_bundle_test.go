package server

import (
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
)

func TestNativeProducerBundleExportsOnlyMatchingCompletedProtocol(t *testing.T) {
	d := hostaction.Digest("binding")
	in := generated.NativeProducerLookupRequest{Schema: generated.SchemaIDNativeProducerLookupRequest, SchemaVersion: "1.0.0", ScopeDigest: d, ScenarioID: "action-replay", HostID: "host-native", PlanID: "plan-native", PlanDigest: d, RunID: "run-native", StepID: "step-native"}
	ref := generated.NativeProducerReference{Schema: generated.SchemaIDNativeProducerReference, SchemaVersion: "1.0.0", ScenarioID: in.ScenarioID, HostID: in.HostID, PlanID: in.PlanID, PlanDigest: d, RunID: in.RunID, StepID: in.StepID, LeaseID: "lease-native"}
	at := time.Now().UTC().Truncate(time.Second)
	b := generated.HostActionBundle{Schema: generated.SchemaIDHostActionBundle, SchemaVersion: "1.0.0", BundleID: "bundle-native", PlanID: ref.PlanID, PlanDigest: ref.PlanDigest, RunID: ref.RunID, StepID: ref.StepID, LeaseID: ref.LeaseID, HostID: ref.HostID, HostIdentityDigest: d, DeclarationID: "declaration-native", DeclarationRevision: 1, StateRevision: 2, RecoveryEpoch: 0, ActionID: "debian.access.collect", ActionVersion: "1.0.0", ActionInput: "{}", ActionInputDigest: hostaction.BytesDigest([]byte("{}")), AutomationPrincipalID: "automation-native", CallerUID: 1001, CredentialReferenceID: "credential-native", CredentialMaterialVersion: "version-native", ConsoleConfirmationDigest: d, IssuedAt: at.Format(time.RFC3339), ExpiresAt: at.Add(time.Minute).Format(time.RFC3339)}
	w := generated.NativeActionProtocolWitness{Schema: generated.SchemaIDNativeActionProtocolWitness, SchemaVersion: "1.0.0", Bundle: b, ScenarioID: in.ScenarioID, CompletedResults: 1, ResultDigest: d}
	for _, kind := range []string{"own", "other-scenario", "non-protocol", "run", "step", "lease", "plan", "host", "epoch", "wrong-action", "unfinished", "two-completions", "input"} {
		t.Run(kind, func(t *testing.T) {
			q, r, witness := in, ref, w
			switch kind {
			case "other-scenario":
				witness.ScenarioID = "action-concurrency"
			case "non-protocol":
				q.ScenarioID, r.ScenarioID, witness.ScenarioID = "baseline-access", "baseline-access", "baseline-access"
			case "run":
				witness.Bundle.RunID = "foreign-run"
			case "step":
				witness.Bundle.StepID = "foreign-step"
			case "lease":
				witness.Bundle.LeaseID = "foreign-lease"
			case "plan":
				witness.Bundle.PlanDigest = hostaction.Digest("foreign-plan")
			case "host":
				witness.Bundle.HostID = "foreign-host"
			case "epoch":
				witness.Bundle.RecoveryEpoch = 1
			case "wrong-action":
				witness.Bundle.ActionID = "debian.access.apply"
			case "unfinished":
				witness.CompletedResults = 0
			case "two-completions":
				witness.CompletedResults = 2
			case "input":
				witness.Bundle.ActionInput = "changed"
			}
			out, err := nativeProducerBundle(q, r, witness)
			if (err == nil) != (kind == "own") {
				t.Fatalf("%s: %v", kind, err)
			}
			if kind == "own" && hostaction.Digest(out) != hostaction.Digest(b) {
				t.Fatal("export rewrote actual completed bundle")
			}
		})
	}
}
