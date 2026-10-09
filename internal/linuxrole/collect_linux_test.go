//go:build linux

package linuxrole

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
)

func TestRoleApplyNetworkRequiresPostRoleCollection(t *testing.T) {
	in := fixture()
	in.ControlIDs = []string{"linux.role-network-boundary"}
	in.RoleBindingDigest = RoleBindingDigest(in)
	raw, _ := json.Marshal(in)
	b := handlerBundle("debian.role.apply")
	b.ActionInput = string(raw)
	b.ActionInputDigest = hostaction.BytesDigest(raw)
	// The existing access collector rejects this fixture version before any OS
	// reads. Exercise the real apply-only pending branch without host access.
	n := &nativeRuntime{version: "fixture-no-native-access", now: time.Now}
	observed, e := n.Collect(context.Background(), b, in)
	if e != nil || len(observed.Measurements) != 1 {
		t.Fatal(observed, e)
	}
	observed.Changed = true
	h, _ := NewHandler(b.ActionID, &testRuntime{out: observed})
	result, e := h.Execute(context.Background(), b)
	if e != nil || hostaction.ValidateResult(result) != nil || !result.EffectObserved || !result.Changed || result.Status != "partial" {
		t.Fatal(result, e)
	}
	m := result.ControlMeasurements[0]
	if m.Status != "partial" || m.Reason != "access-probe-recollection-required" || m.MeasurementDigest != hostaction.MeasurementDigest(m) || result.ResultDigest != hostaction.ResultDigest(result) {
		t.Fatal("initial role apply lost pending observation or canonical digest", result)
	}
}
func TestLaterRoleCollectionPreservesNativeNetworkCandidate(t *testing.T) {
	in := fixture()
	in.ControlIDs = []string{"linux.role-network-boundary"}
	in.RoleBindingDigest = RoleBindingDigest(in)
	raw, _ := json.Marshal(in)
	b := handlerBundle("debian.role.collect")
	b.ActionInput = string(raw)
	b.ActionInputDigest = hostaction.BytesDigest(raw)
	// Existing Runtime seam models the completed native policy read. Central
	// receipt composition still separately requires the actual #225 probes.
	m := incompleteMeasurements(in, hostaction.Digest(b))[0]
	m.Status = "passed"
	m.Reason = "role-network-policy-observed"
	m.Role.Verification = "configuration-observed"
	h, _ := NewHandler(b.ActionID, &testRuntime{out: RoleResult{Measurements: []generated.AccessMeasurement{m}}})
	result, e := h.Execute(context.Background(), b)
	if e != nil || hostaction.ValidateResult(result) != nil || result.Status != "succeeded" || result.Changed || !result.EffectObserved || result.ControlMeasurements[0].Status != "passed" {
		t.Fatal(result, e)
	}
}
