package qualification

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
	"strings"
	"testing"
	"time"
)

func TestNativeFixtureApprovalRequiresActualCurrentPlan(t *testing.T) {
	now := time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)
	digest := "sha256:" + strings.Repeat("a", 64)
	a := generated.NativeSlackFixtureApproval{Schema: generated.SchemaIDNativeSlackFixtureApproval, SchemaVersion: "1.0.0", PlanID: "plan-one", PlanDigest: digest, TargetDigest: digest, ReasonDigest: digest, StateRevision: 2, RecoveryEpoch: 1, ExpiresAt: now.Add(time.Minute).Format(time.RFC3339), Action: "approve"}
	p := generated.Plan{PlanID: a.PlanID, PlanDigest: digest, Status: "planned", AuthorizationBranch: "human", ExpiresAt: a.ExpiresAt, Binding: generated.PlanBinding{TargetDigest: digest, ReasonDigest: digest, StateRevision: 2, RecoveryEpoch: 1}}
	f := generated.NativeSlackFixtureScope{SetupPlanID: "setup-one", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)}
	if validateFixtureApproval(a, p, f, 1, now) != nil {
		t.Fatal("actual plan rejected")
	}
	for _, variant := range []string{"digest", "target", "reason", "revision", "epoch", "expiry", "expired", "setup", "branch", "status"} {
		t.Run(variant, func(t *testing.T) {
			b, q, r := a, p, f
			switch variant {
			case "digest":
				b.PlanDigest = "sha256:" + strings.Repeat("b", 64)
			case "target":
				b.TargetDigest = "sha256:" + strings.Repeat("b", 64)
			case "reason":
				b.ReasonDigest = "sha256:" + strings.Repeat("b", 64)
			case "revision":
				b.StateRevision++
			case "epoch":
				b.RecoveryEpoch++
			case "expiry":
				r.ExpiresAt = now.Add(time.Second).Format(time.RFC3339)
			case "expired":
				b.ExpiresAt = now.Format(time.RFC3339)
				q.ExpiresAt = b.ExpiresAt
			case "setup":
				r.SetupPlanID = b.PlanID
			case "branch":
				q.AuthorizationBranch = "preauthorized"
			case "status":
				q.Status = "applied"
			}
			if validateFixtureApproval(b, q, r, 1, now) == nil {
				t.Fatal("changed binding admitted")
			}
		})
	}
	list := generated.NativeSlackFixtureApprovalList{Schema: generated.SchemaIDNativeSlackFixtureApprovalList, SchemaVersion: "1.0.0", Approvals: []generated.NativeSlackFixtureApproval{}}
	if replaceFixtureApproval(&list, a) != nil || replaceFixtureApproval(&list, a) == nil {
		t.Fatal("publication duplicate boundary")
	}
	a.PlanID = "plan-two"
	if replaceFixtureApproval(&list, a) != nil || len(list.Approvals) != 1 || list.Approvals[0].PlanID != "plan-two" {
		t.Fatal("finite replacement failed")
	}
}
