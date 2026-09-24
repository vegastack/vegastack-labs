package schedule

import (
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

func validPolicy() generated.ScheduledJobPolicy {
	digest := "sha256:" + strings.Repeat("a", 64)
	return generated.ScheduledJobPolicy{
		Schema: generated.SchemaIDScheduledJobPolicy, SchemaVersion: "1.1.0", PolicyID: "policy-a", Revision: 1,
		DeclarationID: "declaration-a", DeclarationRevision: 1, ApprovalPlanID: "plan-a", ApprovalPlanDigest: digest, ApprovedByHumanID: "human-a",
		ActionKind: "backup-create", OperationType: "backup.snapshot", AdapterID: "core.backup", ExactSourceIDs: []string{"source-a"}, ExactSubjectIDs: []string{"subject-a"}, ExactTargetIDs: []string{"target-a"}, MaximumWork: 1,
		CredentialReferenceIDs: []string{"credential-a"}, GrantRevision: 1, StateRevision: 4, RecoveryEpoch: 2, PolicyVersion: "1.0.0", RetentionRuleDigest: digest,
		AnchorAt: "2026-09-16T00:00:00Z", IntervalSeconds: 3600, WindowSeconds: 900, CatchUp: "latest", Concurrency: "forbid", MaxAttempts: 3, InitialBackoffSeconds: 10, MaximumBackoffSeconds: 60,
		ExpiresAt: "2026-10-16T00:00:00Z", Enabled: true,
	}
}

func TestCanonicalPolicyRejectsHumanOnlyAndWidenedActions(t *testing.T) {
	policy := validPolicy()
	if _, digest, err := CanonicalPolicy(policy); err != nil || !strings.HasPrefix(digest, "sha256:") {
		t.Fatalf("valid policy: %s %v", digest, err)
	}
	for _, operation := range []string{"backup.restore", "backup.retention.change", "resource.delete", "identity.change", "shell.grant"} {
		changed := policy
		changed.OperationType = operation
		if _, _, err := CanonicalPolicy(changed); err == nil {
			t.Fatalf("human-only action admitted: %s", operation)
		}
	}
	changed := policy
	changed.ExactTargetIDs = []string{"target-b", "target-a"}
	if _, _, err := CanonicalPolicy(changed); err == nil {
		t.Fatal("unsorted exact targets admitted")
	}
}

func TestScheduledRequestCannotCarryPlanOrHumanAcknowledgement(t *testing.T) {
	raw := []byte(`{"schema":"vegastack-labs.dev/scheduled-job-request","schemaVersion":"1.1.0","expectedStateRevision":4,"recoveryEpoch":2,"targetDigest":"sha256:` + strings.Repeat("a", 64) + `","idempotencyKey":"dispatch-a","policyId":"policy-a","policyRevision":1,"occurrenceToken":"token-a","observedAt":"2026-09-16T00:10:00Z","planId":"plan-a","humanAcknowledgementId":"ack-a"}`)
	if err := generated.ValidateContractJSON(generated.SchemaIDScheduledJobRequest, raw, generated.ContractExact); err == nil {
		t.Fatal("caller-authored plan or acknowledgement accepted")
	}
}
