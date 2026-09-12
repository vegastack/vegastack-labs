package plan

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/stateexport"
)

func canonicalPlan(plan generated.Plan) ([]byte, error) {
	body, _, err := stateexport.CanonicalJSON(plan)
	return body, err
}

func planDigest(plan generated.Plan) (string, error) {
	copy := plan
	copy.PlanID, copy.PlanDigest = "", ""
	_, sum, err := stateexport.CanonicalJSON(copy)
	if err != nil {
		return "", err
	}
	return digest(sum), nil
}

func readablePlan(plan generated.Plan) string {
	var body strings.Builder
	fmt.Fprintf(&body, "Declaration %s revision %d\n", plan.DeclarationID, plan.Binding.DeclarationRevision)
	fmt.Fprintf(&body, "State %d -> %d, recovery epoch %d\n", plan.Binding.PriorStateRevision, plan.Binding.StateRevision, plan.Binding.RecoveryEpoch)
	fmt.Fprintf(&body, "Facts %s\nTargets %s\n", plan.Binding.ObservationFingerprint, plan.Binding.TargetDigest)
	for _, operation := range plan.Operations {
		fmt.Fprintf(&body, "%d. %s %s via %s/%s on %s input=%s artifact=%s idempotent=%t\n", operation.Sequence, operation.OperationID, operation.OperationType, operation.AdapterID, operation.ExecutorID, operation.TargetID, operation.InputDigest, operation.ArtifactDigest, operation.Idempotent)
	}
	return body.String()
}

func targetDigest(operations []generated.PlanOperation) (string, error) {
	targets := make([]string, 0, len(operations))
	seen := map[string]bool{}
	for _, operation := range operations {
		if !seen[operation.TargetID] {
			seen[operation.TargetID] = true
			targets = append(targets, operation.TargetID)
		}
	}
	sort.Strings(targets)
	_, sum, err := stateexport.CanonicalJSON(targets)
	if err != nil {
		return "", err
	}
	return digest(sum), nil
}

func digest(sum [32]byte) string { return "sha256:" + hex.EncodeToString(sum[:]) }
func sha(value []byte) string    { return digest(sha256.Sum256(value)) }
