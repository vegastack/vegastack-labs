package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/debianaccess"
	"github.com/vegastack/vegastack-labs/internal/debianbaseline"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/hostadoption"
	"github.com/vegastack/vegastack-labs/internal/hostdiscovery"
	"github.com/vegastack/vegastack-labs/internal/hostreplacement"
	"strconv"
	"strings"
)

func (s *Store) WorkflowAuthorizationTargets(ctx context.Context, request authorization.Request) (out []authorization.Target, err error) {
	if s == nil || !authorization.WorkflowNavigation(request.Action, request.Target) {
		return nil, actionError(generated.ErrorCodeAuthorizationDenied)
	}
	err = s.Read(ctx, func(tx ReadTx) error {
		var e error
		out, e = workflowAuthorizationTargets(ctx, tx, request)
		return e
	})
	if err != nil {
		out = nil
	}
	return
}

func workflowAuthorizationTargets(ctx context.Context, tx ReadTx, request authorization.Request) ([]authorization.Target, error) {
	action, target := request.Action, request.Target
	if !authorization.WorkflowNavigation(action, target) {
		return nil, actionError(generated.ErrorCodeAuthorizationDenied)
	}
	row := func(q string, a ...any) *sql.Row { return tx.queryRow(ctx, q, a...) }
	if target.ResourceKind == "recovery-point" {
		id, err := recoveryPointPolicy(row, target.ResourceID)
		if err != nil {
			return nil, err
		}
		return []authorization.Target{{Capability: "recovery.restore.author", ResourceKind: "backup-policy", ResourceID: id}}, nil
	}
	var raw []byte
	var reason string
	var plan generated.Plan
	switch target.ResourceKind {
	case "declaration":
		declarationID := target.ResourceID
		revision := request.DeclarationRevision
		if action == authorization.ActionAuthor && revision <= 0 {
			return nil, actionError(generated.ErrorCodeAuthorizationDenied)
		}
		if action == authorization.ActionRead {
			at := strings.LastIndexByte(declarationID, ':')
			if at < 1 {
				return nil, actionError(generated.ErrorCodeAuthorizationDenied)
			}
			parsed, e := strconv.ParseInt(declarationID[at+1:], 10, 64)
			if e != nil || parsed <= 0 || strconv.FormatInt(parsed, 10) != declarationID[at+1:] {
				return nil, actionError(generated.ErrorCodeAuthorizationDenied)
			}
			revision = parsed
			declarationID = declarationID[:at]
		}
		query := `SELECT canonical_bytes,reason_digest FROM declaration_revisions WHERE declaration_id=? AND (?=0 OR declaration_revision=?) ORDER BY declaration_revision DESC LIMIT 1`
		if row(query, declarationID, revision, revision).Scan(&raw, &reason) != nil {
			return nil, actionError(generated.ErrorCodeAuthorizationDenied)
		}
	case "plan", "run":
		var canonical []byte
		var readable string
		query := `SELECT canonical_bytes,readable_plan FROM immutable_plans WHERE plan_id=?`
		if target.ResourceKind == "run" {
			query = `SELECT p.canonical_bytes,p.readable_plan FROM plan_runs r JOIN immutable_plans p ON p.plan_id=r.plan_id AND p.plan_digest=r.plan_digest WHERE r.run_id=?`
		}
		if row(query, target.ResourceID).Scan(&canonical, &readable) != nil || !decodeStoredPlan(canonical, readable, &plan) {
			return nil, actionError(generated.ErrorCodeAuthorizationDenied)
		}
		if row(`SELECT canonical_bytes,reason_digest FROM declaration_revisions WHERE declaration_id=? AND declaration_revision=?`, plan.DeclarationID, plan.Binding.DeclarationRevision).Scan(&raw, &reason) != nil {
			return nil, actionError(generated.ErrorCodeAuthorizationDenied)
		}
	}
	var d generated.DeclarationRevision
	if !decodeStoredDeclaration(raw, reason, &d) {
		return nil, actionError(generated.ErrorCodeAuthorizationDenied)
	}
	if target.ResourceKind != "declaration" {
		if len(d.Operations) != len(plan.Operations) || d.RecoveryEpoch != plan.Binding.RecoveryEpoch {
			return nil, actionError(generated.ErrorCodeIntegrityFailure)
		}
		for i, op := range d.Operations {
			po := plan.Operations[i]
			if op.Sequence != po.Sequence || op.OperationID != po.OperationID || op.OperationType != po.OperationType || op.AdapterID != po.AdapterID || op.TargetID != po.TargetID || op.InputDigest != po.InputDigest || op.ArtifactDigest != po.ArtifactDigest {
				return nil, actionError(generated.ErrorCodeIntegrityFailure)
			}
		}
	}
	if d.AuthorizationGrantBatch != nil {
		if !ValidateGrantBatchDeclaration(d) || (target.ResourceKind != "declaration" && (plan.AuthorizationGrantBatch == nil || hostaction.Digest(plan.AuthorizationGrantBatch) != hostaction.Digest(d.AuthorizationGrantBatch))) {
			return nil, actionError(generated.ErrorCodeAuthorizationDenied)
		}
		capability := "authorization.policy.read"
		if action == authorization.ActionAuthor {
			capability = "authorization.policy.write"
		}
		return []authorization.Target{{Capability: capability, ResourceKind: "authorization-policy", ResourceID: d.AuthorizationGrantBatch.PrincipalID}}, nil
	}
	targets, err := workflowDeclarationTargets(row, d, action)
	if err != nil {
		return nil, err
	}
	if len(targets) == 0 {
		return nil, actionError(generated.ErrorCodeAuthorizationDenied)
	}
	return targets, nil
}

// Only authenticated stored, typed workflow payloads supply resource owners.
// A declaration's arbitrary target or extension is never an ownership claim.
func workflowDeclarationTargets(row discoveryRow, d generated.DeclarationRevision, action authorization.Action) ([]authorization.Target, error) {
	deny := func() ([]authorization.Target, error) {
		return nil, actionError(generated.ErrorCodeAuthorizationDenied)
	}
	targets := []authorization.Target{}
	add := func(authorCap, readCap, kind, id string) {
		cap := readCap
		if action == authorization.ActionAuthor {
			cap = authorCap
		}
		targets = append(targets, authorization.Target{Capability: cap, ResourceKind: kind, ResourceID: id})
	}
	if d.Status != "draft" && d.Status != "committed" {
		return deny()
	}
	if len(d.Operations) == 0 {
		return deny()
	}
	op := d.Operations[0]
	var raw []byte
	var digest string
	switch d.DeclarationType {
	case "authorization.policy":
		if d.AuthorizationGrantBatch == nil || !ValidateGrantBatchDeclaration(d) {
			return deny()
		}
		add("authorization.policy.write", "authorization.policy.read", "authorization-policy", d.AuthorizationGrantBatch.PrincipalID)
	case "host.discovery-target":
		var request generated.HostDiscoveryTargetDraftRequest
		if len(d.Operations) != 1 || row(`SELECT canonical_bytes,digest FROM host_discovery_drafts WHERE draft_id=?`, op.TargetID).Scan(&raw, &digest) != nil || json.Unmarshal(raw, &request) != nil || hostdiscovery.Digest(request) != digest || d.DeclarationID != "discovery-draft-"+digest[7:39] || op.TargetID != d.DeclarationID || op.InputDigest != digest || op.ArtifactDigest != digest || op.AdapterID != "core.host-discovery-target" || op.OperationType != "host.discovery-target."+request.Action {
			return deny()
		}
		add("host.discovery.target.prepare", "host.discovery.collect", "host-discovery-target", request.Target.TargetID)
	case "host.adoption":
		var request generated.HostAdoptionRequest
		if len(d.Operations) != 1 || row(`SELECT canonical_bytes,digest FROM host_adoption_drafts WHERE draft_id=?`, op.TargetID).Scan(&raw, &digest) != nil || json.Unmarshal(raw, &request) != nil || hostadoption.Digest(request) != digest || d.DeclarationID != "host-adoption-"+digest[7:39] || op.TargetID != d.DeclarationID || op.InputDigest != digest || op.ArtifactDigest != digest || op.AdapterID != "core.host-adoption" || op.OperationType != "host.adopt" {
			return deny()
		}
		obs, err := readDiscoveryObservation(row, request.ObservationID)
		if err != nil || obs.ContentDigest != request.ObservationDigest {
			return deny()
		}
		add("host.adoption.prepare", "host.discovery.collect", "host-discovery-target", obs.TargetID)
	case "host.action", "host.access":
		p := generated.Plan{AuthorizationBranch: "human", ExecutorMode: "central"}
		for _, o := range d.Operations {
			p.Operations = append(p.Operations, generated.PlanOperation{Sequence: o.Sequence, OperationID: o.OperationID, OperationType: o.OperationType, AdapterID: o.AdapterID, TargetID: o.TargetID, InputDigest: o.InputDigest, ArtifactDigest: o.ArtifactDigest})
		}
		requests := []generated.HostActionRequest{}
		for _, o := range d.Operations {
			id := "host-action-" + o.ArtifactDigest[7:39]
			if d.DeclarationType == "host.access" {
				id = accessDraftID(o.ArtifactDigest)
			}
			draft, err := readHostActionDraft(row, id)
			if err != nil || draft.Digest != o.ArtifactDigest || draft.Request.HostID != o.TargetID || o.InputDigest == "" {
				return deny()
			}
			requests = append(requests, draft.Request)
			add("host.action.prepare", "host.read", "host", draft.Request.HostID)
			if draft.Request.ActionID == ControlRecoveryReceiveAction {
				var receive generated.ControlRecoveryReceiveInput
				input := []byte(draft.Request.ActionInput)
				if generated.ValidateContractJSON(generated.SchemaIDControlRecoveryReceiveInput, input, generated.ContractExact) != nil || json.Unmarshal(input, &receive) != nil || hostaction.BytesDigest(input) != draft.Request.ActionInputDigest || hostreplacement.ValidateInput(receive.Replacement) != nil || hostreplacement.BindRestore(receive.Replacement, receive.Binding) != nil || receive.Replacement.NewHostID != draft.Request.HostID {
					return deny()
				}
				add("host.action.prepare", "host.read", "host", receive.Replacement.OldHostID)
				add("host.action.prepare", "host.read", "host", receive.Replacement.NewHostID)
			}
			scope, err := debianbaseline.ScopeForRequest(draft.Request)
			if err != nil {
				return deny()
			}
			if scope != nil {
				add("host.action.prepare", "host.read", "host", scope.SubjectHostID)
				add("host.action.prepare", "host.read", "host", scope.ExecutionHostID)
			}
		}
		if d.DeclarationType == "host.action" {
			if len(requests) != 1 || d.DeclarationID != hostaction.DraftID(requests[0]) || op.AdapterID != hostaction.AdapterID || op.OperationType != hostaction.OperationType {
				return deny()
			}
		} else {
			seq, err := debianaccess.Sequence(p.Operations, requests)
			if err != nil || d.DeclarationID != "host-access-"+hostaction.Digest(seq)[7:39] {
				return deny()
			}
			for _, target := range seq.AuxiliaryTargets {
				add("host.action.prepare", "host.read", "host", target.HostID)
			}
		}
	case "host.replacement":
		draft, err := readReplacementDraft(row, op.TargetID)
		kind := hostreplacement.FreezeOperation
		if draft.Request.Operation == "commit" {
			kind = hostreplacement.CommitOperation
		}
		if err != nil || validateReplacementDraftBinding(row, draft) != nil || hostreplacement.ValidateInput(draft.Request) != nil || len(d.Operations) != 1 || d.DeclarationID != "host-replacement-"+draft.Digest[7:39] || op.InputDigest != draft.Digest || op.ArtifactDigest != draft.Digest || op.AdapterID != hostreplacement.AdapterID || op.OperationType != kind {
			return deny()
		}
		add("host.replacement.prepare", "host.read", "host", draft.Request.OldHostID)
		add("host.replacement.prepare", "host.read", "host", draft.Request.NewHostID)
	case "host.alias-claim":
		if !validAliasClaimDeclarationShape(d, hostaction.Digest(d.HostAliasClaim)) {
			return deny()
		}
		add("host.replacement.prepare", "host.read", "host", d.HostAliasClaim.HostID)
		for _, id := range d.HostAliasClaim.AliasIDs {
			add("host.alias.claim", "host.alias.read", "host-alias", id)
		}
	case "gate-profile":
		var scope GateAppliedProfile
		if len(d.Operations) != 1 || op.AdapterID != "core.gate" || op.OperationType != "gate.profile.bind" || d.DeclarationID != "gate-profile-"+op.OperationID || row(`SELECT scope_bytes,scope_digest FROM gate_profile_drafts WHERE binding_id=?`, op.OperationID).Scan(&raw, &digest) != nil || json.Unmarshal(raw, &scope) != nil || gateDigest(raw) != digest || op.TargetID != scope.ProfileID || op.InputDigest != digest || op.ArtifactDigest != digest {
			return deny()
		}
		add("gate.profile.author", "gate.profile.read", "profile", "profile-drafts")
	case "gate-evidence":
		var gateID, subject string
		if len(d.Operations) != 1 || op.AdapterID != "core.gate" || (op.OperationType != "gate.evidence.apply" && op.OperationType != "gate.evidence.supersede" && op.OperationType != "gate.evidence.revoke") || d.DeclarationID != "gate-evidence-"+op.OperationID || row(`SELECT gate_id,subject_id,bundle_digest,bundle_bytes FROM gate_evidence_drafts WHERE evidence_id=?`, op.OperationID).Scan(&gateID, &subject, &digest, &raw) != nil || op.TargetID != subject || op.InputDigest != digest || op.ArtifactDigest != digest {
			return deny()
		}
		add("gate.evidence.author", "gate.read", "gate", strings.ToLower(gateID))
		if gateID == "host.hardening-baseline" || gateID == "host.role-admission" {
			targets = append(targets, authorization.Target{Capability: "host.read", ResourceKind: "host", ResourceID: subject})
		}
	case "recovery.restore":
		var requestBytes, bindingBytes []byte
		var p generated.Plan
		var canonical []byte
		var readable string
		if row(`SELECT p.canonical_bytes,p.readable_plan,q.request_bytes,q.binding_bytes FROM immutable_plans p JOIN restore_plan_qualifications q ON q.plan_id=p.plan_id AND q.plan_digest=p.plan_digest WHERE p.declaration_id=? AND p.declaration_revision=?`, d.DeclarationID, d.Revision).Scan(&canonical, &readable, &requestBytes, &bindingBytes) != nil || !decodeStoredPlan(canonical, readable, &p) {
			return deny()
		}
		var q RestorePlanQualification
		if json.Unmarshal(requestBytes, &q.Request) != nil || json.Unmarshal(bindingBytes, &q.Binding) != nil || !validRestorePlanQualification(q, p) {
			return deny()
		}
		id, err := recoveryPointPolicy(row, q.Request.PointID)
		if err != nil {
			return deny()
		}
		add("recovery.restore.author", "backup.status.read", "backup-policy", id)
		for _, host := range []string{q.Request.FormerHostID, q.Request.ReplacementHostID} {
			if host != "" {
				targets = append(targets, authorization.Target{Capability: "host.read", ResourceKind: "host", ResourceID: host})
			}
		}
	case "credential.lifecycle":
		revision := d.Revision
		if d.Status == "committed" {
			revision--
		}
		for _, o := range d.Operations {
			var b credentialref.LifecycleBinding
			if row(`SELECT binding_bytes,binding_digest FROM credential_lifecycle_bindings WHERE declaration_id=? AND declaration_revision=? AND operation_id=?`, d.DeclarationID, revision, o.OperationID).Scan(&raw, &digest) != nil || json.Unmarshal(raw, &b) != nil || credentialref.LifecycleManifestDigestOf(b) != digest || o.InputDigest != b.CiphertextFingerprint || o.ArtifactDigest != b.CiphertextFingerprint || o.AdapterID != "core.credential" || o.OperationType != string(b.Action) || o.TargetID != b.TargetID {
				return deny()
			}
			add("credential.lifecycle.author", "credential.reference.read", "credential-reference", b.ReferenceID)
		}
	default:
		if len(d.Operations) != 1 || op.AdapterID != "local.backup" {
			return nil, nil
		}
		switch op.OperationType {
		case "backup.local.create":
			for _, e := range d.Extensions {
				if e.Name == "x-backup-policy" {
					digest = e.ValueDigest
				}
			}
			var policy generated.BackupPolicy
			if digest == "" || row(`SELECT canonical_json FROM backup_policy_drafts WHERE policy_digest=? AND recovery_epoch=?`, digest, d.RecoveryEpoch).Scan(&raw) != nil || hostaction.BytesDigest(raw) != digest || json.Unmarshal(raw, &policy) != nil || generated.ValidateContractJSON(generated.SchemaIDBackupPolicy, raw, generated.ContractExact) != nil || (op.TargetID != policy.PolicyID && op.TargetID != policy.RestoreTargetID) {
				return deny()
			}
			add("backup.execute", "backup.status.read", "backup-policy", policy.PolicyID)
		case "backup.local.verify":
			var manifest, inventory string
			if row(`SELECT manifest_digest,inventory_digest FROM recovery_points WHERE point_id=?`, op.TargetID).Scan(&manifest, &inventory) != nil || op.InputDigest != manifest || op.ArtifactDigest != inventory {
				return deny()
			}
			id, err := recoveryPointPolicy(row, op.TargetID)
			if err != nil {
				return deny()
			}
			add("backup.execute", "backup.status.read", "backup-policy", id)
		default:
			return nil, nil
		}
	}
	unique := map[authorization.Target]bool{}
	out := []authorization.Target{}
	for _, t := range targets {
		if !authorization.ValidAuthorizationTarget(t) {
			return deny()
		}
		if !unique[t] {
			unique[t] = true
			out = append(out, t)
		}
	}
	return out, nil
}

func (s *Store) DraftBackupAuthorizationTargets(ctx context.Context, in generated.DeclarationRevisionRequest) ([]authorization.Target, error) {
	if s == nil || len(in.Operations) != 1 || in.Operations[0].AdapterID != "local.backup" {
		return nil, actionError(generated.ErrorCodeAuthorizationDenied)
	}
	raw, err := json.Marshal(in)
	if err != nil || generated.ValidateContractJSON(generated.SchemaIDDeclarationRevisionRequest, raw, generated.ContractExact) != nil {
		return nil, actionError(generated.ErrorCodeInputInvalid)
	}
	d := generated.DeclarationRevision{DeclarationID: in.DeclarationID, DeclarationType: in.DeclarationType, Status: "draft", Revision: in.ExpectedRevision, StateRevision: in.ExpectedStateRevision + 1, RecoveryEpoch: in.RecoveryEpoch, Operations: in.Operations, Extensions: in.Extensions}
	var out []authorization.Target
	err = s.Read(ctx, func(tx ReadTx) error {
		var e error
		out, e = workflowDeclarationTargets(func(q string, a ...any) *sql.Row { return tx.queryRow(ctx, q, a...) }, d, authorization.ActionAuthor)
		return e
	})
	if err == nil && len(out) == 0 {
		err = actionError(generated.ErrorCodeAuthorizationDenied)
	}
	return out, err
}

func workflowAuthorRequiresAdministrator(t authorization.Target) bool {
	return t.ResourceKind == "host" || t.ResourceKind == "host-alias" || t.ResourceKind == "host-discovery-target" || t.ResourceKind == "authorization-policy"
}
