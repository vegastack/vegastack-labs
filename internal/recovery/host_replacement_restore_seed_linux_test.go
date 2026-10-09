//go:build linux

package recovery

import (
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/hostdiscovery"
	"github.com/vegastack/vegastack-labs/internal/hostreplacement"
	"github.com/vegastack/vegastack-labs/internal/linuxrole"
	"golang.org/x/crypto/ssh"
)

// Seed only synthetic pre-existing authoritative records. The caller performs
// the actual snapshot, frozen history, candidate restore and canary workflow.
func seedReplacementRestoreHosts(t *testing.T, db *sql.DB, source generated.RestoreSourceBinding) generated.HostReplacementRequest {
	t.Helper()
	ex := func(q string, a ...any) { t.Helper(); replacementRestoreExec(t, db, q, a...) }
	enc := replacementRestoreJSON
	digest := hostaction.Digest
	ex(`INSERT INTO effective_authorization_principals VALUES('restore-human','human','active',1,'now','now')`)
	raw, err := os.ReadFile("../gate/testdata/linux-role-input.json")
	if err != nil {
		t.Fatal(err)
	}
	var base generated.LinuxRoleInput
	if json.Unmarshal(raw, &base) != nil {
		t.Fatal("role fixture")
	}
	q := generated.HostReplacementRequest{Schema: generated.SchemaIDHostReplacementRequest, SchemaVersion: "1.0.0", ReplacementID: "replacement-a", Operation: "freeze", RestorationClass: "control-database", OldHostID: "old-host", NewHostID: "new-host", OldIdentityDigest: digest("old-host"), NewIdentityDigest: digest("new-host"), OldTargetRevision: 1, NewTargetRevision: 1, ProfileID: base.ProfileID, ProfileLockDigest: base.ProfileLockDigest, RoleDeclarationID: "old-role", RoleDeclarationRevision: 1, ProposedRoleDeclarationID: "new-role", ProposedRoleDeclarationRevision: 1, PayloadIDs: []string{}, VolumeIDs: []string{}, ResourceIDs: []string{}, ExpectedStateRevision: 1, RecoveryEpoch: source.RecoveryEpoch, IdempotencyKey: "replacement-freeze", Source: &generated.HostReplacementSourceReference{Schema: generated.SchemaIDHostReplacementSourceReference, SchemaVersion: "1.0.0", PointID: source.PointID, ManifestDigest: source.ManifestDigest, SourceBindingDigest: digest(source), CustodyReferenceID: "custody-a", CustodyBindingDigest: digest("custody")}}
	for _, host := range []string{q.OldHostID, q.NewHostID} {
		var in generated.LinuxRoleInput
		_ = json.Unmarshal(raw, &in)
		in.HostID = host
		in.HostIdentityDigest = digest(host)
		in.NetworkAccess.HostID = host
		in.NetworkAccess.HostIdentityDigest = in.HostIdentityDigest
		in.NetworkAccess.RollbackSpecification.HostID = host
		in.NetworkAccess.RollbackSpecification.HostIdentityDigest = in.HostIdentityDigest
		in.NetworkAccess.RollbackDigest = digest(in.NetworkAccess.RollbackSpecification)
		in.RenderedPolicyDigest = linuxrole.PolicyDigest(in)
		in.RoleBindingDigest = linuxrole.RoleBindingDigest(in)
		if err := linuxrole.ValidateInput(in); err != nil {
			t.Fatal(err)
		}
		public, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		key, err := ssh.NewPublicKey(public)
		if err != nil {
			t.Fatal(err)
		}
		target := generated.HostDiscoveryTarget{Schema: generated.SchemaIDHostDiscoveryTarget, SchemaVersion: "1.0.0", TargetID: "target-" + host, Revision: 1, Address: "192.0.2.2", Port: 22, User: "inspect", HostKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))), ProfileID: in.ProfileID, CredentialReferenceID: "credential-" + host, MaterialVersion: "v1", ExpectedOS: "debian", ExpectedVersion: "13.6", ExpectedArchitecture: "amd64", RecoveryEpoch: source.RecoveryEpoch}
		if err := hostdiscovery.ValidateTarget(target); err != nil {
			t.Fatal(err)
		}
		draft := generated.HostDiscoveryTargetDraftRequest{Schema: generated.SchemaIDHostDiscoveryTargetDraftRequest, SchemaVersion: "1.0.0", Target: target, Action: "activate", IdempotencyKey: target.TargetID}
		td := digest(draft)
		roleID := "old-role"
		if host == q.NewHostID {
			roleID = "new-role"
		}
		request := generated.HostActionRequest{Schema: generated.SchemaIDHostActionRequest, SchemaVersion: "1.0.0", HostID: host, TargetRevision: 1, TargetDigest: td, ActionID: "debian.role.apply", ActionVersion: "1.0.0", ActionInput: string(enc(in)), ActionInputDigest: hostaction.BytesDigest(enc(in)), CallerUID: in.AutomationUID, AutomationPrincipalID: "automation-a", CredentialReferenceID: target.CredentialReferenceID, CredentialMaterialVersion: "v1", ConsoleConfirmation: generated.HostActionConsoleConfirmation{Schema: generated.SchemaIDHostActionConsoleConfirmation, SchemaVersion: "1.0.0", Method: "administrator-verified-console", TargetDigest: td, HostIdentityDigest: in.HostIdentityDigest}, ExpectedStateRevision: 1, RecoveryEpoch: source.RecoveryEpoch, IdempotencyKey: roleID}
		if err := hostaction.ValidateRequest(request); err != nil {
			t.Fatal(err)
		}
		scope, err := linuxrole.ScopeForRequest(request)
		if err != nil {
			t.Fatal(err)
		}
		declaration := generated.DeclarationRevision{Schema: generated.SchemaIDDeclarationRevision, SchemaVersion: "1.0.0", DeclarationID: roleID, DeclarationType: "host.action", Revision: 1, StateRevision: 1, RecoveryEpoch: source.RecoveryEpoch, Status: "draft", CreatedAt: "2026-10-09T12:00:00Z", CreatedBy: "restore-human", AgentSessionID: "replacement-fixture", Operations: []generated.DeclarationOperation{{Sequence: 1, OperationID: "role", OperationType: "host.action.execute", AdapterID: "host-action", TargetID: host, InputDigest: digest(request), ArtifactDigest: digest(request), Idempotent: true}}, Extensions: []generated.ContractExtension{}}
		reason := digest(roleID)
		declaration.ContentDigest = digest(struct {
			DeclarationID   string                           `json:"declarationId"`
			DeclarationType string                           `json:"declarationType"`
			Operations      []generated.DeclarationOperation `json:"operations"`
			ReasonDigest    string                           `json:"reasonDigest"`
			Extensions      []generated.ContractExtension    `json:"extensions"`
		}{declaration.DeclarationID, declaration.DeclarationType, declaration.Operations, reason, declaration.Extensions})
		ex(`INSERT INTO declaration_revisions VALUES(?,1,'host.action',1,?,?,?,'draft',?,'now','restore-human','fixture')`, roleID, source.RecoveryEpoch, declaration.ContentDigest, reason, enc(declaration))
		plan := generated.Plan{PlanID: "plan-" + host, PlanDigest: digest("plan-" + host), DeclarationID: roleID, HostAction: &request, HostRoleScope: scope, Binding: generated.PlanBinding{StateRevision: 1, DeclarationRevision: 1, RecoveryEpoch: source.RecoveryEpoch}, Operations: []generated.PlanOperation{{Sequence: 1, OperationID: "role", OperationType: "host.action.execute", AdapterID: "host-action", TargetID: host, InputDigest: digest(request), ArtifactDigest: digest(request)}}}
		pd := plan.PlanDigest
		ex(`INSERT INTO immutable_plans VALUES(?,?,?,1,1,?,?,?,?,?,?,?,'2026-01-01T00:00:00Z','2026-12-01T00:00:00Z')`, plan.PlanID, pd, roleID, source.RecoveryEpoch, pd, pd, pd, enc(plan), "fixture", pd)
		ex(`INSERT INTO host_action_drafts VALUES(?,?,?,'restore-human',1,?)`, roleID, digest(request), enc(request), source.RecoveryEpoch)
		ex(`INSERT INTO host_discovery_drafts VALUES(?,?,1,0,'activate',?,?,'restore-human',1,?)`, target.TargetID, target.TargetID, td, enc(draft), source.RecoveryEpoch)
		ex(`INSERT INTO host_discovery_targets VALUES(?,1,?,'active',?,?)`, target.TargetID, target.TargetID, plan.PlanID, source.RecoveryEpoch)
		observation := generated.HostObservation{ObservationID: "observation-" + host, TargetID: target.TargetID, TargetDigest: td, TargetRevision: 1, ContentDigest: digest("observed-" + host)}
		ex(`INSERT INTO host_discovery_attempts VALUES(?,'restore-human',?,?,?,1,?,1,0,?,'later',?)`, observation.ObservationID, td, td, target.TargetID, td, source.RecoveryEpoch, []byte(`{}`))
		ex(`INSERT INTO host_observations VALUES(?,?,1,?,?,0,?)`, observation.ObservationID, target.TargetID, enc(observation), digest(observation), source.RecoveryEpoch)
		ex(`INSERT INTO host_adoption_drafts VALUES(?,?,?,'restore-human',1,?)`, host, td, []byte(`{}`), source.RecoveryEpoch)
		ex(`INSERT INTO acknowledgement_requests VALUES(?,?,?,?,?,'restore-human','fixture-authority',?,1,?,'later','approved',?,?,'now','now','now')`, "ack-"+host, plan.PlanID, pd, pd, pd, pd, source.RecoveryEpoch, []byte(`{}`), []byte(`{}`))
		ex(`INSERT INTO managed_hosts VALUES(?,?,?,'product-serial','qualified-virtual',?,?,?,?,'restore-human',?,1,?)`, host, target.TargetID, in.HostIdentityDigest, observation.ObservationID, in.ProfileID, host, plan.PlanID, "ack-"+host, source.RecoveryEpoch)
		ex(`INSERT INTO effective_authorization_grants VALUES(?,'restore-human','infrastructure-admin','read','host.read','host',?,NULL,1,'active','now','now')`, "read-"+host, host)
		ex(`INSERT INTO plan_runs VALUES(?,?,?,'decision',NULL,'1.0.0','central','executor',?,'succeeded',0,'not-requested','pending',NULL,0,1,?,?,?,?,'now','now')`, "run-"+host, plan.PlanID, pd, pd, source.RecoveryEpoch, pd, pd, []byte(`{}`))
		ex(`INSERT INTO plan_run_steps(step_id,run_id,sequence,operation_id,operation_type,adapter_id,executor_id,target_id,input_digest,artifact_digest,idempotent,status,effect_state,result_digest,started_at,finished_at) VALUES(?,?,1,'role','host.action.execute','host-action','executor',?,?,?,1,'succeeded','verified',?,'now','now')`, "step-"+host, "run-"+host, host, pd, pd, pd)
		kd, _ := hostreplacement.SSHHostKeyDigest(target.HostKey)
		if host == q.OldHostID {
			q.OldTargetDigest = td
			q.OldSSHHostKeyDigest = kd
			q.OldRoleBindingDigest = in.RoleBindingDigest
		} else {
			q.NewTargetDigest = td
			q.NewSSHHostKeyDigest = kd
			q.ProposedRoleBindingDigest = in.RoleBindingDigest
			q.PreservedPreimageDigest = hostreplacement.RolePreimageDigest(in)
			q.OSPreparation = generated.HostReplacementOsPreparation{Schema: generated.SchemaIDHostReplacementOsPreparation, SchemaVersion: "1.0.0", Method: "administrator-prepared", ObservationID: observation.ObservationID, ObservationDigest: observation.ContentDigest, HostIdentityDigest: in.HostIdentityDigest, ConfirmedAt: "2026-10-09T12:00:00Z"}
		}
	}
	q.AliasBindings = []generated.HostReplacementAliasBinding{{Schema: generated.SchemaIDHostReplacementAliasBinding, SchemaVersion: "1.0.0", AliasID: "control-alias", OwnerHostID: q.OldHostID, OwnerIdentityDigest: q.OldIdentityDigest, OwnerRevision: 1, OwnershipGeneration: 1}}
	if err := hostreplacement.ValidateInput(q); err != nil {
		t.Fatal(err)
	}
	return q
}
