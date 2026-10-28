package operations

import (
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"testing"
	"time"
)

func notificationFixture(at time.Time) NotificationReceipts {
	r := NotificationReceipts{ReferenceDigest: Digest("refs"), RunID: "run-test", PlanID: "plan-test", PlanDigest: Digest("plan"), StepID: "step-test", LeaseID: "lease-test", PolicyDigest: Digest("policy"), HumanID: "human-test", RecoveryEpoch: 2}
	for _, phase := range []string{"failure", "recovery"} {
		state := "open"
		if phase == "recovery" {
			state = "closed"
		}
		r.Receipts = append(r.Receipts, NotificationReceipt{Route: "github", Phase: phase, ProviderID: 17, State: state, AcceptedAt: at.Add(-time.Minute).Format(time.RFC3339Nano), ResponseDigest: Digest(phase)}, NotificationReceipt{Route: "slack", Phase: phase, State: "provider-accepted", AcceptedAt: at.Add(-time.Minute).Format(time.RFC3339Nano), ResponseDigest: Digest("ok")})
	}
	return r
}
func TestNotificationReceiptsRequireActualCompleteCurrentExactRoutePhases(t *testing.T) {
	now := time.Now().UTC()
	base := notificationFixture(now)
	if _, e := ValidateNotificationReceipts(base, base.PolicyDigest, 2, now); e != nil {
		t.Fatal(e)
	}
	b := NotificationBundle(base, now.Add(-time.Minute))
	raw, _ := json.Marshal(b)
	if e := generated.ValidateContractJSON(generated.SchemaIDGateEvidenceBundle, raw, generated.ContractExact); e != nil {
		t.Fatal(e)
	}
	for name, change := range map[string]func(*NotificationReceipts){"incomplete": func(r *NotificationReceipts) { r.Receipts = r.Receipts[:3] }, "duplicate": func(r *NotificationReceipts) { r.Receipts[3] = r.Receipts[1] }, "rebound": func(r *NotificationReceipts) { r.PolicyDigest = Digest("new-route") }, "epoch": func(r *NotificationReceipts) { r.RecoveryEpoch++ }, "wrong-issue": func(r *NotificationReceipts) { r.Receipts[2].ProviderID++ }, "not-closed": func(r *NotificationReceipts) { r.Receipts[2].State = "open" }, "human-read-claim": func(r *NotificationReceipts) { r.Receipts[1].State = "human-read" }, "future": func(r *NotificationReceipts) { r.Receipts[1].AcceptedAt = now.Add(time.Minute).Format(time.RFC3339) }, "expired": func(r *NotificationReceipts) {
		r.Receipts[0].AcceptedAt = now.Add(-25 * time.Hour).Format(time.RFC3339)
	}, "no-human-ack": func(r *NotificationReceipts) { r.HumanID = "" }} {
		t.Run(name, func(t *testing.T) {
			r := base
			r.Receipts = append([]NotificationReceipt(nil), base.Receipts...)
			change(&r)
			if _, e := ValidateNotificationReceipts(r, base.PolicyDigest, 2, now); e == nil {
				t.Fatal("unproven readiness accepted")
			}
		})
	}
}
