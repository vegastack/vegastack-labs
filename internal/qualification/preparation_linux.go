//go:build linux

package qualification

import (
	"bytes"
	"context"
	"encoding/json"
	nativecredential "github.com/vegastack/vegastack-labs/internal/adapter/nativecredential"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"strconv"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/hostreplacement"
	"github.com/vegastack/vegastack-labs/internal/localapi"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
)

func executePreparation(ctx context.Context, scope validatedNativeScope, step generated.NativeStepRequest, out generated.NativeStepResult) (generated.NativeStepResult, error) {
	raw, err := ownedFile(filepath.Join("/run/vsk-labs-native", step.ScenarioID+"-"+strconv.FormatInt(step.Ordinal, 10)+".prepare.json"), 0, 65536)
	var in generated.NativePreparationRequest
	if err != nil || generated.ValidateContractJSON(generated.SchemaIDNativePreparationRequest, raw, generated.ContractExact) != nil || json.Unmarshal(raw, &in) != nil || hostaction.Digest(in.Binding) != hostaction.Digest(step) || validatePreparation(scope, in) != nil {
		return out, ErrUnavailable
	}
	if in.Kind == "fixture-approval" {
		if err = publishFixtureApproval(ctx, scope, in); err != nil {
			return out, err
		}
		out.Status = "completed"
		out.Changed = true
		return out, nil
	}
	reply, err := callNativeAPI(ctx, scope, nativeAPIPacket{Step: step, Kind: "prepare", Preparation: &in})
	if err != nil {
		return out, err
	}
	return reply.Result, nil
}

// A preparation slot holds exactly one existing typed API input. It cannot
// select a URL, command, identity, plaintext material or database connection.
// Import selects only a closed, administrator-prepared private fixture slot.
func validatePreparation(scope validatedNativeScope, in generated.NativePreparationRequest) error {
	if in.Binding.Operation != "prepare" {
		return ErrUnavailable
	}
	selected := generated.NativePreparationRequest{Schema: in.Schema, SchemaVersion: in.SchemaVersion, Binding: in.Binding, Kind: in.Kind}
	g, ok := scope.guests[in.Binding.GuestID]
	if !ok {
		return ErrUnavailable
	}
	switch in.Kind {
	case "profile":
		if in.Profile == nil || in.Profile.ProfileID != scope.value.ProfileID || in.Profile.RecoveryEpoch != in.Binding.RecoveryEpoch {
			return ErrUnavailable
		}
		selected.Profile = in.Profile
	case "credential-import":
		if in.CredentialImport == nil {
			return ErrUnavailable
		}
		c := in.CredentialImport
		if c.TargetID != g.HostID || c.ReferenceID != "native-ssh-"+g.HostID || c.ConsumerID != hostaction.AdapterID || c.PurposeID != hostaction.PurposeID || c.ResolverID != "native-systemd" || c.RecoveryEpoch != in.Binding.RecoveryEpoch || (in.CredentialSlot != g.Role+"-ssh" && in.CredentialSlot != "previous-ssh" && in.CredentialSlot != "current-ssh") {
			return ErrUnavailable
		}
		selected.CredentialImport, selected.CredentialSlot = c, in.CredentialSlot
	case "database-status":
		// No caller-selected target or request body.
	case "grant-batch":
		if in.GrantBatch == nil || in.GrantBatch.RecoveryEpoch != in.Binding.RecoveryEpoch {
			return ErrUnavailable
		}
		allowed := map[string]bool{scope.value.ProfileID: true, "profile-drafts": true}
		for _, guest := range scope.guests {
			allowed[guest.HostID] = true
			allowed["native-ssh-"+guest.HostID] = true
		}
		for _, grant := range in.GrantBatch.Changes {
			if !allowed[grant.ResourceID] {
				return ErrUnavailable
			}
		}
		selected.GrantBatch = in.GrantBatch
	case "producer-lookup":
		if in.ProducerLookup == nil || in.ProducerLookup.ScopeDigest != scope.digest || in.ProducerLookup.ScenarioID != in.Binding.ScenarioID || in.ProducerLookup.HostID != g.HostID || in.ProducerLookup.RecoveryEpoch != in.Binding.RecoveryEpoch {
			return ErrUnavailable
		}
		selected.ProducerLookup = in.ProducerLookup
	case "fixture-approval":
		if in.FixtureApproval == nil || in.FixtureApproval.RecoveryEpoch != in.Binding.RecoveryEpoch {
			return ErrUnavailable
		}
		selected.FixtureApproval = in.FixtureApproval
	case "target":
		if in.Target == nil || in.Target.Target.ProfileID != scope.value.ProfileID || in.Target.Target.RecoveryEpoch != in.Binding.RecoveryEpoch {
			return ErrUnavailable
		}
		digest, err := hostreplacement.SSHHostKeyDigest(in.Target.Target.HostKey)
		if err != nil || digest != g.SSHHostKeyDigest {
			return ErrUnavailable
		}
		selected.Target = in.Target
	case "discover":
		if in.Discovery == nil || in.Discovery.RecoveryEpoch != in.Binding.RecoveryEpoch {
			return ErrUnavailable
		}
		selected.Discovery = in.Discovery
	case "adopt":
		if in.Adoption == nil || in.Adoption.HostID != g.HostID || in.Adoption.RecoveryEpoch != in.Binding.RecoveryEpoch {
			return ErrUnavailable
		}
		selected.Adoption = in.Adoption
	case "access":
		if in.Access == nil || in.Access.Subject.HostID != g.HostID || in.Access.Subject.RecoveryEpoch != in.Binding.RecoveryEpoch {
			return ErrUnavailable
		}
		selected.Access = in.Access
	case "action":
		if in.Action == nil || in.Action.HostID != g.HostID || in.Action.RecoveryEpoch != in.Binding.RecoveryEpoch {
			return ErrUnavailable
		}
		selected.Action = in.Action
	case "replacement":
		if in.Replacement == nil || in.Replacement.RecoveryEpoch != in.Binding.RecoveryEpoch {
			return ErrUnavailable
		}
		hosts := map[string]string{}
		for _, guest := range scope.guests {
			hosts[guest.HostID] = guest.HostIdentityDigest
		}
		if hosts[in.Replacement.OldHostID] != in.Replacement.OldIdentityDigest || hosts[in.Replacement.NewHostID] != in.Replacement.NewIdentityDigest {
			return ErrUnavailable
		}
		selected.Replacement = in.Replacement
	case "credential-lifecycle":
		if in.CredentialLifecycle == nil || in.CredentialLifecycle.RecoveryEpoch != in.Binding.RecoveryEpoch {
			return ErrUnavailable
		}
		selected.CredentialLifecycle = in.CredentialLifecycle
	case "backup-policy":
		if in.BackupPolicy == nil || in.BackupPolicy.RecoveryEpoch != in.Binding.RecoveryEpoch {
			return ErrUnavailable
		}
		selected.BackupPolicy = in.BackupPolicy
	case "backup-run":
		if in.BackupRun == nil || in.BackupRun.RecoveryEpoch != in.Binding.RecoveryEpoch {
			return ErrUnavailable
		}
		selected.BackupRun = in.BackupRun
	case "backup-verify":
		if in.BackupVerify == nil || in.BackupVerify.RecoveryEpoch != in.Binding.RecoveryEpoch {
			return ErrUnavailable
		}
		selected.BackupVerify = in.BackupVerify
	case "restore-plan":
		if in.RestorePlan == nil || in.RestorePlan.RecoveryEpoch != in.Binding.RecoveryEpoch {
			return ErrUnavailable
		}
		hosts := map[string]bool{}
		for _, guest := range scope.guests {
			hosts[guest.HostID] = true
		}
		if !hosts[in.RestorePlan.FormerHostID] || !hosts[in.RestorePlan.ReplacementHostID] || in.RestorePlan.FormerHostID == in.RestorePlan.ReplacementHostID {
			return ErrUnavailable
		}
		selected.RestorePlan = in.RestorePlan
	case "restore-run":
		if in.RestoreRun == nil || in.RestoreRun.RecoveryEpoch != in.Binding.RecoveryEpoch {
			return ErrUnavailable
		}
		selected.RestoreRun = in.RestoreRun
	case "restore-verify":
		if in.RestoreVerify == nil || in.RestoreVerify.RecoveryEpoch != in.Binding.RecoveryEpoch {
			return ErrUnavailable
		}
		selected.RestoreVerify = in.RestoreVerify
	case "plan":
		if in.DeclarationID == "" || in.DeclarationRevision < 1 {
			return ErrUnavailable
		}
		selected.DeclarationID = in.DeclarationID
		selected.DeclarationRevision = in.DeclarationRevision
	case "approval":
		if in.Approval == nil || in.Approval.RecoveryEpoch != in.Binding.RecoveryEpoch {
			return ErrUnavailable
		}
		selected.Approval = in.Approval
	case "approval-status", "replacement-state":
		if in.Identifier == "" {
			return ErrUnavailable
		}
		selected.Identifier = in.Identifier
	case "host":
		if in.Identifier != g.HostID {
			return ErrUnavailable
		}
		selected.Identifier = in.Identifier
	case "gate":
		if in.GateID == "" {
			return ErrUnavailable
		}
		selected.GateID = in.GateID
	default:
		return ErrUnavailable
	}
	if hostaction.Digest(selected) != hostaction.Digest(in) {
		return ErrUnavailable
	}
	return nil
}

func preparationResult[T any](response localapi.TypedResponse[T]) generated.NativePreparationResult {
	return generated.NativePreparationResult{Schema: generated.SchemaIDNativePreparationResult, SchemaVersion: "1.0.0", Result: response.Result, ExitCode: int64(response.ExitCode)}
}
func dispatchPreparation(ctx context.Context, c localapi.Client, p serverconfig.Profile, in generated.NativePreparationRequest) (generated.NativePreparationResult, error) {
	var out generated.NativePreparationResult
	switch in.Kind {
	case "profile":
		r, e := c.SubmitProfileDraft(ctx, p, *in.Profile)
		out = preparationResult(r)
		if e == nil && r.ExitCode == 0 {
			out.Profile = &r.Data
		}
		return out, e
	case "credential-import":
		raw, e := readFixtureImportMaterial(ctx, p.SocketOwnerUID, in.CredentialSlot)
		if e != nil {
			return out, ErrUnavailable
		}
		defer func() {
			for i := range raw {
				raw[i] = 0
			}
		}()
		r, e := c.ImportCredential(ctx, p, *in.CredentialImport, bytes.NewReader(raw))
		out = preparationResult(r)
		if e == nil && r.ExitCode == 0 {
			out.CredentialImport = &r.Data
		}
		return out, e
	case "database-status":
		r, e := c.DatabaseStatus(ctx, p)
		out = preparationResult(r)
		if e == nil && r.ExitCode == 0 {
			out.DatabaseStatus = &r.Data
		}
		return out, e
	case "grant-batch":
		r, e := c.DraftAuthorizationGrants(ctx, p, *in.GrantBatch)
		out = preparationResult(r)
		if e == nil && r.ExitCode == 0 {
			out.GrantDeclaration = &r.Data
		}
		return out, e
	case "producer-lookup":
		r, e := c.LookupNativeProducerReference(ctx, p, *in.ProducerLookup)
		out = preparationResult(r)
		if e == nil && r.ExitCode == 0 {
			out.ProducerReference = &r.Data.ProducerReference
			out.ActionBundle = r.Data.ActionBundle
		}
		return out, e
	case "target":
		r, e := c.PrepareHostTarget(ctx, p, *in.Target)
		out = preparationResult(r)
		if e == nil && r.ExitCode == 0 {
			out.Target = &r.Data
		}
		return out, e
	case "discover":
		r, e := c.DiscoverHost(ctx, p, *in.Discovery)
		out = preparationResult(r)
		if e == nil && r.ExitCode == 0 {
			out.Discovery = &r.Data
		}
		return out, e
	case "adopt":
		r, e := c.SubmitHostAdoption(ctx, p, *in.Adoption)
		out = preparationResult(r)
		if e == nil && r.ExitCode == 0 {
			out.Adoption = &r.Data
		}
		return out, e
	case "access":
		r, e := c.SubmitHostAccess(ctx, p, *in.Access)
		out = preparationResult(r)
		if e == nil && r.ExitCode == 0 {
			out.Action = &r.Data
		}
		return out, e
	case "action":
		r, e := c.SubmitHostAction(ctx, p, *in.Action)
		out = preparationResult(r)
		if e == nil && r.ExitCode == 0 {
			out.Action = &r.Data
		}
		return out, e
	case "replacement":
		r, e := c.PrepareHostReplacement(ctx, p, *in.Replacement)
		out = preparationResult(r)
		if e == nil && r.ExitCode == 0 {
			out.Replacement = &r.Data
		}
		return out, e
	case "replacement-state":
		r, e := c.GetHostReplacement(ctx, p, in.Identifier)
		out = preparationResult(r)
		if e == nil && r.ExitCode == 0 {
			out.ReplacementState = &r.Data
		}
		return out, e
	case "credential-lifecycle":
		r, e := c.CreateCredentialLifecycleDraft(ctx, p, *in.CredentialLifecycle)
		out = preparationResult(r)
		if e == nil && r.ExitCode == 0 {
			out.CredentialLifecycle = &r.Data
		}
		return out, e
	case "backup-policy":
		r, e := c.SubmitBackupPolicyDraft(ctx, p, *in.BackupPolicy)
		out = preparationResult(r)
		if e == nil && r.ExitCode == 0 {
			out.BackupPolicy = &r.Data
		}
		return out, e
	case "backup-run":
		r, e := c.RunDatabaseBackup(ctx, p, *in.BackupRun)
		out = preparationResult(r)
		if e == nil && r.ExitCode == 0 {
			out.BackupJob = &r.Data
		}
		return out, e
	case "backup-verify":
		r, e := c.VerifyDatabase(ctx, p, *in.BackupVerify)
		out = preparationResult(r)
		if e == nil && r.ExitCode == 0 {
			out.BackupJob = &r.Data
		}
		return out, e
	case "restore-plan":
		r, e := c.PlanRestore(ctx, p, *in.RestorePlan)
		out = preparationResult(r)
		if e == nil && r.ExitCode == 0 {
			out.RestoreBinding = &r.Data
		}
		return out, e
	case "restore-run":
		r, e := c.RunRestore(ctx, p, *in.RestoreRun)
		out = preparationResult(r)
		if e == nil && r.ExitCode == 0 {
			out.RestoreBinding = &r.Data
		}
		return out, e
	case "restore-verify":
		r, e := c.VerifyRestore(ctx, p, *in.RestoreVerify)
		out = preparationResult(r)
		if e == nil && r.ExitCode == 0 {
			out.RestoreVerification = &r.Data
		}
		return out, e
	case "plan":
		r, e := c.Plan(ctx, p, in.DeclarationID, in.DeclarationRevision)
		out = preparationResult(r)
		if e == nil && r.ExitCode == 0 {
			out.Plan = &r.Data
		}
		return out, e
	case "approval":
		r, e := c.RequestPlanApproval(ctx, p, *in.Approval)
		out = preparationResult(r)
		if e == nil && r.ExitCode == 0 {
			out.Approval = &r.Data
		}
		return out, e
	case "approval-status":
		r, e := c.GetPlanApproval(ctx, p, in.Identifier)
		out = preparationResult(r)
		if e == nil && r.ExitCode == 0 {
			out.Approval = &r.Data
		}
		return out, e
	case "host":
		r, e := c.GetManagedHost(ctx, p, in.Identifier)
		out = preparationResult(r)
		if e == nil && r.ExitCode == 0 {
			out.Host = &r.Data
		}
		return out, e
	case "gate":
		r, e := c.GetGate(ctx, p, in.GateID)
		out = preparationResult(r)
		if e == nil && r.ExitCode == 0 {
			out.Gate = &r.Data
		}
		return out, e
	}
	return out, ErrUnavailable
}

// No caller path or credential bytes enter a native preparation request.
func readFixtureImportMaterial(ctx context.Context, uid uint32, slot string) ([]byte, error) {
	return readFixtureImportMaterialAt(ctx, "/run/vsk-labs-control-credentials", uid, slot)
}

func readFixtureImportMaterialAt(ctx context.Context, root string, uid uint32, slot string) ([]byte, error) {
	name := map[string]string{"controller-ssh": "native-ssh-controller", "subject-ssh": "native-ssh-subject", "custodian-ssh": "native-ssh-custodian", "replacement-ssh": "native-ssh-replacement", "previous-ssh": "native-previous-ssh", "current-ssh": "native-current-ssh"}[slot]
	if name == "" || uid == 0 || uint32(os.Geteuid()) != uid {
		return nil, ErrUnavailable
	}
	if ownedDirectory(root, uid) != nil {
		return nil, ErrUnavailable
	}
	fd, e := unix.Openat2(unix.AT_FDCWD, root, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if e != nil {
		return nil, ErrUnavailable
	}
	dir := os.NewFile(uintptr(fd), "fixture-import-directory")
	defer dir.Close()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Uid != uid || st.Mode&0777 != 0700 {
		return nil, ErrUnavailable
	}
	return nativecredential.ReadLoadedBytes(ctx, dir, name, uid)
}
