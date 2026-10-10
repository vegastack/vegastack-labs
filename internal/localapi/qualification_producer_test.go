package localapi

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"testing"
	"time"
)

func TestNativeProducerClientBindsActualReference(t *testing.T) {
	in := generated.NativeProducerLookupRequest{Schema: generated.SchemaIDNativeProducerLookupRequest, SchemaVersion: "1.0.0", ScopeDigest: hostaction.Digest("scope"), ScenarioID: "baseline-access", HostID: "host-a", PlanID: "plan-a", PlanDigest: hostaction.Digest("plan"), RunID: "run-a", StepID: "step-a", RecoveryEpoch: 0}
	for _, kind := range []string{"own", "run", "host", "epoch"} {
		t.Run(kind, func(t *testing.T) {
			data := generated.NativeProducerReference{Schema: generated.SchemaIDNativeProducerReference, SchemaVersion: "1.0.0", ScenarioID: in.ScenarioID, HostID: in.HostID, PlanID: in.PlanID, PlanDigest: in.PlanDigest, RunID: in.RunID, StepID: in.StepID, LeaseID: "actual-lease"}
			epoch := int64(0)
			if kind == "run" {
				data.RunID = "other-run"
			}
			if kind == "host" {
				data.HostID = "other-host"
			}
			if kind == "epoch" {
				epoch = 1
			}
			_, profile, captured := serveFixedResponse(t, 200, operationEnvelope(t, "api.v1.qualification.producer", false, epoch, 2, generated.NativeProducerLookupData{Schema: generated.SchemaIDNativeProducerLookupData, SchemaVersion: "1.0.0", ProducerReference: data}))
			_, err := NewClient(clientTestFactory()).LookupNativeProducerReference(context.Background(), profile, in)
			select {
			case <-captured:
			default:
				t.Fatal("no actual request")
			}
			if (err == nil) != (kind == "own") {
				t.Fatalf("kind=%s error=%v", kind, err)
			}
		})
	}
}

func TestNativeProducerClientRequiresExactProtocolBundle(t *testing.T) {
	d := hostaction.Digest("pin")
	in := generated.NativeProducerLookupRequest{Schema: generated.SchemaIDNativeProducerLookupRequest, SchemaVersion: "1.0.0", ScopeDigest: d, ScenarioID: "action-concurrency", HostID: "host-a", PlanID: "plan-a", PlanDigest: d, RunID: "run-a", StepID: "step-a"}
	for _, kind := range []string{"own", "missing", "extra-non-protocol", "lease", "action", "epoch", "plan", "host", "input"} {
		t.Run(kind, func(t *testing.T) {
			q := in
			ref := generated.NativeProducerReference{Schema: generated.SchemaIDNativeProducerReference, SchemaVersion: "1.0.0", ScenarioID: q.ScenarioID, HostID: q.HostID, PlanID: q.PlanID, PlanDigest: q.PlanDigest, RunID: q.RunID, StepID: q.StepID, LeaseID: "lease-a"}
			at := time.Now().UTC().Truncate(time.Second)
			b := generated.HostActionBundle{Schema: generated.SchemaIDHostActionBundle, SchemaVersion: "1.0.0", BundleID: "bundle-a", PlanID: ref.PlanID, PlanDigest: d, RunID: ref.RunID, StepID: ref.StepID, LeaseID: ref.LeaseID, HostID: ref.HostID, HostIdentityDigest: d, DeclarationID: "declaration-a", DeclarationRevision: 1, StateRevision: 2, ActionID: "debian.access.collect", ActionVersion: "1.0.0", ActionInput: "{}", ActionInputDigest: hostaction.BytesDigest([]byte("{}")), AutomationPrincipalID: "automation-a", CallerUID: 1001, CredentialReferenceID: "credential-a", CredentialMaterialVersion: "version-a", ConsoleConfirmationDigest: d, IssuedAt: at.Format(time.RFC3339), ExpiresAt: at.Add(time.Minute).Format(time.RFC3339)}
			data := generated.NativeProducerLookupData{Schema: generated.SchemaIDNativeProducerLookupData, SchemaVersion: "1.0.0", ProducerReference: ref, ActionBundle: &b}
			switch kind {
			case "missing":
				data.ActionBundle = nil
			case "extra-non-protocol":
				q.ScenarioID, data.ProducerReference.ScenarioID = "baseline-access", "baseline-access"
			case "lease":
				b.LeaseID = "other-lease"
			case "action":
				b.ActionID = "debian.access.apply"
			case "epoch":
				b.RecoveryEpoch = 1
			case "plan":
				b.PlanDigest = hostaction.Digest("other-plan")
			case "host":
				b.HostID = "other-host"
			case "input":
				b.ActionInput = "different"
			}
			_, profile, captured := serveFixedResponse(t, 200, operationEnvelope(t, "api.v1.qualification.producer", false, 0, 2, data))
			out, err := NewClient(clientTestFactory()).LookupNativeProducerReference(context.Background(), profile, q)
			<-captured
			if (err == nil) != (kind == "own") {
				t.Fatalf("%s: %v", kind, err)
			}
			if kind == "own" && (out.Data.ActionBundle == nil || hostaction.Digest(*out.Data.ActionBundle) != hostaction.Digest(b)) {
				t.Fatal("client rewrote completed bundle")
			}
		})
	}
}
