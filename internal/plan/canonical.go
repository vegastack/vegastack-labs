package plan

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/stateexport"
)

func canonicalPlan(plan generated.Plan) ([]byte, error) {
	body, _, err := stateexport.CanonicalJSON(plan)
	if plan.HostAccessSequence != nil && len(body) > 1048576 {
		return nil, planError(generated.ErrorCodeInputInvalid)
	}
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
	if plan.ReplacementContinuity != nil {
		raw, _, _ := stateexport.CanonicalJSON(plan.ReplacementContinuity)
		fmt.Fprintf(&body, "Preserve current host and alias ownership history across this restore: %s\n", raw)
	}
	if plan.HostReplacement != nil {
		raw, _, _ := stateexport.CanonicalJSON(plan.HostReplacement)
		fmt.Fprintf(&body, "Host replacement exact intent: %s\nFreeze prevents new authority on the former host. Commit moves only the named aliases after current denial and qualification; no disk reset, workload move or automatic rollback.\n", raw)
	}
	if plan.AuthorizationGrantBatch != nil {
		raw, _, _ := stateexport.CanonicalJSON(plan.AuthorizationGrantBatch)
		fmt.Fprintf(&body, "Exact authorization grant changes for existing principal: %s\nEffective only after this plan receives human acknowledgement and executes.\n", raw)
	}
	if plan.HostAliasClaim != nil {
		raw, _, _ := stateexport.CanonicalJSON(plan.HostAliasClaim)
		fmt.Fprintf(&body, "Initial alias ownership claim: %s\nOnly unowned aliases may be claimed; registration alone does not qualify this host.\n", raw)
	}
	if plan.NativeRestart != nil {
		raw, _, _ := stateexport.CanonicalJSON(plan.NativeRestart)
		fmt.Fprintf(&body, "Complete prior interrupted native credential restart: %s\nThis new approval verifies the exact current invocation and credential readers without repeating the restart. The prior partial run remains historical.\n", raw)
	}
	if plan.HostActionConsole != nil {
		raw, _, _ := stateexport.CanonicalJSON(plan.HostActionConsole)
		fmt.Fprintf(&body, "Credential consumer console confirmation: %s\nAdministrator confirms independent console access for BOTH the exact destination host/pinned key and the named native consumer/controller machine. Controller unit %s may restart during activation or rotation; native credential loading and denied-reader probes remain required.\n", raw, plan.HostActionNativeUnit)
	}
	if scope := plan.HostRoleScope; scope != nil {
		raw, _, _ := stateexport.CanonicalJSON(scope)
		fmt.Fprintf(&body, "\nLinux role %s on %s; exact role scope: %s\nRole installation does not grant workload admission.\n", scope.RoleID, scope.SubjectHostID, raw)
	}
	if scope := plan.HostBaselineScope; scope != nil {
		raw, _, _ := stateexport.CanonicalJSON(scope)
		fmt.Fprintf(&body, "\nDebian baseline: subject %s; executor %s; role %s; selected controls %s.\nExact baseline scope: %s\n", scope.SubjectHostID, scope.ExecutionHostID, scope.RoleID, strings.Join(scope.ControlIDs, ", "), raw)
		if plan.HostAction != nil {
			var in generated.DebianBaselineInput
			if json.Unmarshal([]byte(plan.HostAction.ActionInput), &in) == nil && in.HostID != "" {
				fmt.Fprintf(&body, "Action %s; time owner %s; update owner %s; audit paths=%v; recovery sources=%v.\n", plan.HostAction.ActionID, in.TimeOwner, in.UpdateOwner, in.AuditPaths, in.RecoverySourcePrefixes)
				for _, profile := range in.AppArmorProfiles {
					fmt.Fprintf(&body, "AppArmor package %s profile %s digest %s.\n", profile.PackageName, profile.ProfileID, profile.ProfileDigest)
				}
				for _, resource := range in.Resources {
					fmt.Fprintf(&body, "Resource limits for %s: memory %d bytes, tasks %d, CPU %d percent; mount %s minimum free %d bytes / %d percent.\n", resource.Unit, resource.MemoryMaxBytes, resource.TasksMax, resource.CPUQuotaPercent, resource.MountPath, resource.MinimumFreeBytes, resource.MinimumFreePercent)
				}
				for _, kernel := range in.KernelSettings {
					fmt.Fprintf(&body, "Kernel setting %s=%s.\n", kernel.Name, kernel.Value)
				}
				if len(in.AIDE.ScopePaths) > 0 {
					fmt.Fprintf(&body, "AIDE paths=%v; prior database digest %s; approved change %s.\n", in.AIDE.ScopePaths, in.AIDE.PreviousDigest, in.AIDE.ApprovedChangeDigest)
				}
				for _, volume := range in.Volumes {
					fmt.Fprintf(&body, "Observe existing encrypted volume %s mapper %s mount %s; independent recovery custodian %s; header %s and keyslot %d. No format or new volume creation.\n", volume.VolumeID, volume.MapperName, volume.MountPath, volume.RecoveryCustodianID, volume.HeaderDigest, volume.KeySlot)
				}
			}
		}

	}
	if plan.HostAccessSequence != nil {
		raw, _, _ := stateexport.CanonicalJSON(plan.HostAccessSequence)
		if len(plan.HostAccessSequence.Actions) > 0 {
			var access generated.DebianAccessInput
			if json.Unmarshal([]byte(plan.HostAccessSequence.Actions[0].ActionInput), &access) == nil {
				fmt.Fprintf(&body, "Debian access on %s; profile %s. Local rollback deadline:600 seconds.\n", access.HostID, access.ProfileID)
				for _, account := range access.Accounts {
					fmt.Fprintf(&body, "Account %s role=%s uid=%d gid=%d home=%s public-key digests=%v\n", account.Name, account.Role, account.UID, account.GID, account.Home, account.PublicKeyDigests)
				}
				fmt.Fprintf(&body, "SSH permitted users=%v; sources=%v; independent recovery sources=%v. Password and ordinary root login disabled.\n", access.SSHUsers, access.SSHSourcePrefixes, access.RecoverySourcePrefixes)
				for _, key := range access.PrivilegedServiceKeys {
					fmt.Fprintf(&body, "Restricted root service key %s fingerprint=%s sources=%v; no ordinary human root access.\n", key.ServiceID, key.PublicKeyDigest, key.SourcePrefixes)
				}
				for _, group := range []struct {
					name  string
					flows []generated.AccessFlow
				}{{"host", access.HostFlows}, {"container", access.ContainerFlows}} {
					for _, flow := range group.flows {
						fmt.Fprintf(&body, "%s firewall permit %s %s -> %s:%d interface=%s\n", group.name, flow.Protocol, flow.SourcePrefix, flow.DestinationPrefix, flow.Port, flow.Interface)
					}
				}
			}
		}
		fmt.Fprintf(&body, "Finite Debian access sequence and all contacted targets: %s\nApply keeps a 600-second local rollback armed until fresh independent probes and exact confirm succeed. All named subject/source/witness identities are included in this acknowledgement.\n", raw)
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
