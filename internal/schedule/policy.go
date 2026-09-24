package schedule

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/stateexport"
)

var actionOperations = map[string]map[string]bool{
	"gate-check":              {"health.check": true},
	"observation-refresh":     {"drift.scan": true},
	"backup-create":           {"backup.snapshot": true},
	"backup-integrity-verify": {"backup.verify": true},
	"audit-checkpoint-export": {"audit.checkpoint": true},
}

// CanonicalPolicy validates and canonicalizes an exact fixed schedule. It
// carries references and digests only; action credentials remain server-side.
func CanonicalPolicy(policy generated.ScheduledJobPolicy) ([]byte, string, error) {
	raw, err := json.Marshal(policy)
	if err != nil || generated.ValidateContractJSON(generated.SchemaIDScheduledJobPolicy, raw, generated.ContractExact) != nil {
		return nil, "", errors.New("invalid scheduled policy contract")
	}
	if policy.SchemaVersion != "1.1.0" || !policy.Enabled || policy.Concurrency != "forbid" || policy.WindowSeconds < int64(generated.PlanValiditySeconds) || policy.WindowSeconds > policy.IntervalSeconds || policy.MaximumBackoffSeconds < policy.InitialBackoffSeconds {
		return nil, "", errors.New("invalid scheduled policy bounds")
	}
	anchor, anchorErr := time.Parse(time.RFC3339, policy.AnchorAt)
	expires, expiresErr := time.Parse(time.RFC3339, policy.ExpiresAt)
	if anchorErr != nil || expiresErr != nil || !expires.After(anchor) {
		return nil, "", errors.New("invalid scheduled policy lifetime")
	}
	allowed, ok := actionOperations[policy.ActionKind]
	if !ok || !allowed[policy.OperationType] || !authorization.IsPreauthorizedOperation(policy.OperationType) {
		return nil, "", errors.New("scheduled action is not preauthorized")
	}
	for _, ids := range [][]string{policy.ExactSourceIDs, policy.ExactSubjectIDs, policy.ExactTargetIDs, policy.CredentialReferenceIDs} {
		if !sortedUnique(ids) {
			return nil, "", errors.New("scheduled bindings must be sorted and unique")
		}
	}
	canonical, sum, err := stateexport.CanonicalJSON(policy)
	if err != nil {
		return nil, "", err
	}
	return canonical, "sha256:" + hex.EncodeToString(sum[:]), nil
}

func sortedUnique(values []string) bool {
	if len(values) == 0 || !sort.StringsAreSorted(values) {
		return false
	}
	for index := 1; index < len(values); index++ {
		if values[index-1] == values[index] {
			return false
		}
	}
	return true
}

type ActionBinding struct {
	Kind                   string
	OperationType          string
	AdapterID              string
	SourceIDs              []string
	SubjectIDs             []string
	TargetIDs              []string
	MaximumWork            int64
	CredentialReferenceIDs []string
	InputDigest            string
	ArtifactDigest         string
}

func BuildAction(policy generated.ScheduledJobPolicy) (ActionBinding, error) {
	if _, _, err := CanonicalPolicy(policy); err != nil {
		return ActionBinding{}, err
	}
	return ActionBinding{
		Kind: policy.ActionKind, OperationType: policy.OperationType, AdapterID: policy.AdapterID,
		SourceIDs: append([]string(nil), policy.ExactSourceIDs...), SubjectIDs: append([]string(nil), policy.ExactSubjectIDs...), TargetIDs: append([]string(nil), policy.ExactTargetIDs...),
		MaximumWork: policy.MaximumWork, CredentialReferenceIDs: append([]string(nil), policy.CredentialReferenceIDs...), InputDigest: policy.RetentionRuleDigest, ArtifactDigest: policy.ApprovalPlanDigest,
	}, nil
}
