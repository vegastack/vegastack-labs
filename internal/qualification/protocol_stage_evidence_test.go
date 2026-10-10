package qualification

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"testing"
	"time"
)

func protocolWitnessFixture() (generated.NativeActionProtocolWitness, generated.NativeActionReceiptWitness) {
	d := hostaction.Digest("binding")
	now := time.Now().UTC().Truncate(time.Second)
	b := generated.HostActionBundle{Schema: generated.SchemaIDHostActionBundle, SchemaVersion: "1.0.0", ActionID: "debian.access.collect", ActionVersion: "1.0.0", ActionInput: "{}", ActionInputDigest: hostaction.BytesDigest([]byte("{}")), BundleID: "bundle-native", PlanID: "plan-native", PlanDigest: d, RunID: "run-native", StepID: "step-native", LeaseID: "lease-native", HostID: "host-native", HostIdentityDigest: d, DeclarationID: "declaration-native", DeclarationRevision: 1, StateRevision: 2, RecoveryEpoch: 0, AutomationPrincipalID: "automation-native", CallerUID: 1001, CredentialReferenceID: "credential-native", CredentialMaterialVersion: "version-native", ConsoleConfirmationDigest: d, IssuedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(time.Minute).Format(time.RFC3339)}
	digest, _ := hostaction.BundleDigest(b)
	denial := generated.HostActionDenial{Schema: generated.SchemaIDHostActionDenial, SchemaVersion: "1.0.0", Code: generated.ErrorCodeAuthorizationDenied, Phase: "execution-claim", BundleDigest: digest, ExecutionDigest: hostaction.ExecutionDigest(b), ClaimDigest: hostaction.Digest("actual claim"), ResultDigest: hostaction.Digest("actual result")}
	w := generated.NativeActionProtocolWitness{Schema: generated.SchemaIDNativeActionProtocolWitness, SchemaVersion: "1.0.0", Bundle: b, ScenarioID: "action-concurrency", ConcurrentAttempts: 3, CompletedResults: 1, ConcurrentDenials: []generated.HostActionDenial{denial, denial}, ReplayDenial: denial, ReplayAfterDenial: denial, ResultDigest: denial.ResultDigest, ObservedAt: now.Format(time.RFC3339), NegativeAttempts: []generated.NativeActionNegativeObservation{}}
	for _, kind := range []string{"malformed-envelope", "wrong-host", "wrong-plan", "wrong-epoch", "invalid-signature"} {
		w.NegativeAttempts = append(w.NegativeAttempts, generated.NativeActionNegativeObservation{Schema: generated.SchemaIDNativeActionNegativeObservation, SchemaVersion: "1.0.0", Variant: kind, Denial: generated.HostActionDenial{Schema: generated.SchemaIDHostActionDenial, SchemaVersion: "1.0.0", Code: generated.ErrorCodeAuthorizationDenied, Phase: "envelope"}})
	}
	receipt := generated.NativeActionReceiptWitness{Schema: generated.SchemaIDNativeActionReceiptWitness, SchemaVersion: "1.0.0", Bundle: b, ExecutionDigest: denial.ExecutionDigest, BundleDigest: digest, ClaimDigest: denial.ClaimDigest, ResultDigest: denial.ResultDigest, Status: "succeeded", ObservedAt: now.Add(time.Second).Format(time.RFC3339)}
	return w, receipt
}

func TestProtocolEvidenceRejectsGenericFailureAndChangedTargetState(t *testing.T) {
	w, r := protocolWitnessFixture()
	if err := validateProtocolWitness("action-concurrency", w, r, r, r.ObservedAt); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*generated.NativeActionProtocolWitness, *generated.NativeActionReceiptWitness){
		"two-writers": func(w *generated.NativeActionProtocolWitness, _ *generated.NativeActionReceiptWitness) {
			w.CompletedResults = 2
		},
		"authorization-not-claim": func(w *generated.NativeActionProtocolWitness, _ *generated.NativeActionReceiptWitness) {
			w.ReplayDenial.Phase = "authorization"
		},
		"wrong-claim": func(w *generated.NativeActionProtocolWitness, _ *generated.NativeActionReceiptWitness) {
			w.ReplayAfterDenial.ClaimDigest = hostaction.Digest("changed")
		},
		"missing-negatives": func(w *generated.NativeActionProtocolWitness, _ *generated.NativeActionReceiptWitness) {
			w.NegativeAttempts = w.NegativeAttempts[:4]
		},
		"duplicate-negative": func(w *generated.NativeActionProtocolWitness, _ *generated.NativeActionReceiptWitness) {
			w.NegativeAttempts[1] = w.NegativeAttempts[0]
		},
		"changed-target-result": func(_ *generated.NativeActionProtocolWitness, r *generated.NativeActionReceiptWitness) {
			r.ResultDigest = hostaction.Digest("changed")
		},
		"other-execution": func(_ *generated.NativeActionProtocolWitness, r *generated.NativeActionReceiptWitness) {
			r.Bundle.LeaseID = "other"
		},
		"partial-result": func(_ *generated.NativeActionProtocolWitness, r *generated.NativeActionReceiptWitness) {
			r.Status = "partial"
		},
	} {
		t.Run(name, func(t *testing.T) {
			w, r := protocolWitnessFixture()
			before := r
			change(&w, &r)
			if validateProtocolWitness("action-concurrency", w, before, r, r.ObservedAt) == nil {
				t.Fatal("incomplete protocol evidence accepted")
			}
		})
	}
}
