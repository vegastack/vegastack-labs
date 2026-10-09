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
	if plan.NativeRestart != nil {
		raw, _, _ := stateexport.CanonicalJSON(plan.NativeRestart)
		fmt.Fprintf(&body, "Complete prior interrupted native credential restart: %s\nThis new approval verifies the exact current invocation and credential readers without repeating the restart. The prior partial run remains historical.\n", raw)
	}
	if plan.HostActionConsole != nil {
		raw, _, _ := stateexport.CanonicalJSON(plan.HostActionConsole)
		fmt.Fprintf(&body, "Credential consumer console confirmation: %s\nAdministrator confirms independent console access for this exact current machine and pinned target key. Native credential loading and denied-reader probes remain required.\n", raw)
	}
	if plan.HostAction != nil {
		raw, _, _ := stateexport.CanonicalJSON(plan.HostAction)
		fmt.Fprintf(&body, "Exact privileged host action and current console confirmation: %s\nAdministrator attestation: I independently verified this machine, pinned key and available console recovery access. This approves only the displayed action, not host admission.\n", raw)
	}
	if plan.HostAdoption != nil {
		r := plan.HostAdoption
		c := r.Confirmation
		fmt.Fprintf(&body, "Register host %s as adopted-unadmitted; no machine changes.\nTarget revision %d binding/key digest %s\nIdentity %s/%s digest %s; confirmed %s\nAdministrator attestation: I independently verified this exact machine and its identity against the pinned target key. Acknowledging this plan approves that confirmation, not workload admission.\n", r.HostID, c.TargetRevision, c.TargetDigest, c.IdentityClass, c.IdentityKind, c.IdentityDigest, c.ConfirmedAt)
	}
	if plan.HostDiscoveryTarget != nil {
		r := plan.HostDiscoveryTarget
		raw, _, _ := stateexport.CanonicalJSON(r)
		fmt.Fprintf(&body, "Discovery-only target %s: %s\nExact target and administrator confirmation: %s\nAcknowledging this plan confirms independent machine identity and console access. No host configuration, global credential qualification or workload admission.\n", r.Target.TargetID, r.Action, raw)
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
