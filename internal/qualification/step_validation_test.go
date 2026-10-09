package qualification

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"testing"
	"time"
)

func TestStepCannotInventInitialLeaseOrBroadenPreparedScope(t *testing.T) {
	scope, err := validateScope(scopeFixture())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	request := generated.NativeStepRequest{Schema: generated.SchemaIDNativeStepRequest, SchemaVersion: "1.0.0", ScopeDigest: scope.digest, GuestID: "subject", ScenarioID: "baseline-access", Ordinal: 1, ControllerInstanceID: "controller-database", RecoveryEpoch: 0, PlanID: "plan-native", PlanDigest: hostaction.Digest("plan"), Nonce: hostaction.Digest("nonce"), Deadline: now.Add(time.Minute).Format(time.RFC3339), Operation: "execute"}
	if err = validateStep(scope, request, now); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*generated.NativeStepRequest){
		"pretend-lease":    func(r *generated.NativeStepRequest) { r.LeaseID = "lease-made-up" },
		"other-controller": func(r *generated.NativeStepRequest) { r.ControllerInstanceID = "other" },
		"unknown-scenario": func(r *generated.NativeStepRequest) { r.ScenarioID = "shell" },
		"other-guest":      func(r *generated.NativeStepRequest) { r.GuestID = "outside" },
		"expired":          func(r *generated.NativeStepRequest) { r.Deadline = now.Format(time.RFC3339) },
		"over-duration":    func(r *generated.NativeStepRequest) { r.Deadline = now.Add(2 * time.Hour).Format(time.RFC3339) },
		"observe-no-lease": func(r *generated.NativeStepRequest) { r.Operation = "observe" },
	} {
		t.Run(name, func(t *testing.T) {
			r := request
			change(&r)
			if validateStep(scope, r, now) == nil {
				t.Fatal("invalid step admitted")
			}
		})
	}
}
