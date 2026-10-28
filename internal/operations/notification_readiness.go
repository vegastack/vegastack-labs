package operations

import (
	"encoding/json"
	"fmt"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"time"
)

const ReadinessAdapter = "operations.notification-readiness"
const ReadinessOperation = "operations.notification-readiness.test"
const ReadinessCollector = "server-notification-readiness-v1"
const ReadinessGithubPurpose = "operations.readiness.github"
const ReadinessSlackPurpose = "operations.readiness.slack"

type NotificationReceipt struct {
	Route          string `json:"route"`
	Phase          string `json:"phase"`
	ProviderID     int64  `json:"providerId"`
	State          string `json:"state"`
	AcceptedAt     string `json:"acceptedAt"`
	ResponseDigest string `json:"responseDigest"`
}
type NotificationReceipts struct {
	ReferenceDigest string                `json:"referenceDigest"`
	RunID           string                `json:"runId"`
	PlanID          string                `json:"planId"`
	PlanDigest      string                `json:"planDigest"`
	StepID          string                `json:"stepId"`
	LeaseID         string                `json:"leaseId"`
	PolicyDigest    string                `json:"policyDigest"`
	HumanID         string                `json:"humanId"`
	RecoveryEpoch   int64                 `json:"recoveryEpoch"`
	Receipts        []NotificationReceipt `json:"receipts"`
}

func NotificationDigest(v any) string { b, _ := json.Marshal(v); return Digest(string(b)) }
func NotificationPolicyDigest(p generated.NotificationReadinessPolicy, g generated.OperationsGithubDestination) string {
	return NotificationDigest(struct {
		Policy  generated.NotificationReadinessPolicy
		Primary generated.OperationsGithubDestination
	}{p, g})
}
func ReadinessCapability(digest string) string {
	if !digestPattern.MatchString(digest) {
		return ""
	}
	return "operations.readiness." + digest[7:]
}
func ValidateNotificationReceipts(r NotificationReceipts, policy string, epoch int64, now time.Time) (time.Time, error) {
	if !digestPattern.MatchString(r.ReferenceDigest) || r.RunID == "" || r.PlanID == "" || r.StepID == "" || r.LeaseID == "" || r.HumanID == "" || r.PolicyDigest != policy || r.RecoveryEpoch != epoch || !digestPattern.MatchString(r.PlanDigest) || len(r.Receipts) != 4 {
		return time.Time{}, ErrInvalid
	}
	seen := map[string]bool{}
	var first time.Time
	var githubID int64
	for _, receipt := range r.Receipts {
		key := receipt.Route + "." + receipt.Phase
		if seen[key] || !digestPattern.MatchString(receipt.ResponseDigest) {
			return first, ErrInvalid
		}
		seen[key] = true
		t, e := time.Parse(time.RFC3339Nano, receipt.AcceptedAt)
		if e != nil || t.After(now) || now.Sub(t) > 24*time.Hour {
			return first, ErrInvalid
		}
		if first.IsZero() || t.Before(first) {
			first = t
		}
		if receipt.Phase != "failure" && receipt.Phase != "recovery" {
			return first, ErrInvalid
		}
		switch receipt.Route {
		case "github":
			want := "open"
			if receipt.Phase == "recovery" {
				want = "closed"
			}
			if receipt.ProviderID <= 0 || receipt.State != want || githubID != 0 && githubID != receipt.ProviderID {
				return first, ErrInvalid
			}
			githubID = receipt.ProviderID
		case "slack":
			if receipt.ProviderID != 0 || receipt.State != "provider-accepted" {
				return first, ErrInvalid
			}
		default:
			return first, fmt.Errorf("invalid notification receipt")
		}
	}
	for _, key := range []string{"github.failure", "slack.failure", "github.recovery", "slack.recovery"} {
		if !seen[key] {
			return first, ErrInvalid
		}
	}
	return first, nil
}
func NotificationFacts(r NotificationReceipts) []generated.GateEvidenceFact {
	return []generated.GateEvidenceFact{{Schema: generated.SchemaIDGateEvidenceFact, SchemaVersion: "1.1.0", FactID: "notification-policy", ValueDigest: r.PolicyDigest}, {Schema: generated.SchemaIDGateEvidenceFact, SchemaVersion: "1.1.0", FactID: "provider-accepted-receipts", ValueDigest: NotificationDigest(r)}}
}
func NotificationBundle(r NotificationReceipts, observed time.Time) generated.GateEvidenceBundle {
	facts := NotificationFacts(r)
	return generated.GateEvidenceBundle{Schema: generated.SchemaIDGateEvidenceBundle, SchemaVersion: "1.1.0", CollectorID: ReadinessCollector, ObservedAt: observed.UTC().Truncate(time.Second).Format(time.RFC3339), Facts: facts, Checks: []generated.GateEvidenceCheck{{Schema: generated.SchemaIDGateEvidenceCheck, SchemaVersion: "1.1.0", VerifierVersion: "1.0.0", CheckID: "notification-provider-acceptance", Result: "passed", ResultDigest: NotificationDigest(facts)}}, Attachments: []generated.GateEvidenceAttachment{}}
}
