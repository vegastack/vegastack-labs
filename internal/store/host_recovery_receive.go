package store

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/hostadoption"
	"github.com/vegastack/vegastack-labs/internal/hostreplacement"
	"github.com/vegastack/vegastack-labs/internal/linuxrole"
)

const ControlRecoveryReceiveAction = "debian.control.recovery-receive"

// ResolveRecoveryReceivePreparation reads only existing staged authority. Byte
// streams remain outside SQLite; the collector must hash them before drafting.
func (r *HostActionRepository) ResolveRecoveryReceivePreparation(ctx context.Context, b generated.RestoreBinding) (out generated.ControlRecoveryReceiveInput, err error) {
	if r == nil || r.store == nil {
		return out, actionError(generated.ErrorCodePrerequisiteBlocked)
	}
	err = r.store.Read(ctx, func(tx ReadTx) error {
		var e error
		out, e = recoveryReceivePreparation(ctx, tx, b)
		return e
	})
	return
}
func recoveryReceivePreparation(ctx context.Context, tx ReadTx, b generated.RestoreBinding) (out generated.ControlRecoveryReceiveInput, err error) {
	deny := func() (generated.ControlRecoveryReceiveInput, error) {
		return generated.ControlRecoveryReceiveInput{}, actionError(generated.ErrorCodePrerequisiteBlocked)
	}
	if !validRestoreBinding(b) || b.ReplacementContinuity == nil {
		return deny()
	}
	row := func(q string, a ...any) *sql.Row { return tx.queryRow(ctx, q, a...) }
	if e := validateRecoveryReceiveContinuity(ctx, tx, b); e != nil {
		return out, e
	}
	var raw []byte
	out.Schema = generated.SchemaIDControlRecoveryReceiveInput
	out.SchemaVersion = "1.0.0"
	if row(`SELECT s.binding_bytes,c.database_digest,c.journal_digest,c.bundle_digest FROM recovery_candidates c JOIN restore_sessions s ON s.plan_id=c.plan_id WHERE c.plan_id=? AND (SELECT t.to_status FROM restore_transitions t WHERE t.plan_id=c.plan_id ORDER BY t.transition_id DESC LIMIT 1)='verification-required'`, b.PlanID).Scan(&raw, &out.DatabaseDigest, &out.JournalDigest, &out.BundleDigest) != nil || json.Unmarshal(raw, &out.Binding) != nil || hostaction.Digest(out.Binding) != hostaction.Digest(b) {
		return deny()
	}
	event, _, e := readReplacementEvent(row, b.ReplacementContinuity.ReplacementID)
	if e != nil || event.State.Status != "frozen" {
		return deny()
	}
	draft, e := readReplacementDraft(row, event.Execution.DraftID)
	if e != nil || draft.BindingDigest != event.State.BindingDigest || hostreplacement.BindRestore(draft.Request, b) != nil || validateReplacementHosts(row, draft.Request) != nil {
		return deny()
	}
	out.Replacement = draft.Request
	for _, id := range []string{draft.Request.OldHostID, draft.Request.NewHostID} {
		if _, e = adoptionGrant(ctx, row, id, "host", "read", "host.read", false); e != nil {
			return out, e
		}
		if _, e = adoptionGrant(ctx, row, id, "host", "author", "host.action.prepare", true); e != nil {
			return out, e
		}
	}
	role, e := readHostActionDraft(row, draft.Request.ProposedRoleDeclarationID)
	if e != nil {
		return deny()
	}
	out.RoleInput, e = linuxrole.DecodeInput([]byte(role.Request.ActionInput))
	if e != nil || out.RoleInput.RoleID != "control" || len(out.RoleInput.Accounts) != 1 {
		return deny()
	}
	out.ServiceUID = out.RoleInput.Accounts[0].UID
	out.ServiceGID = out.RoleInput.Accounts[0].GID
	obs, e := readDiscoveryObservation(row, draft.Request.OSPreparation.ObservationID)
	if e != nil {
		return deny()
	}
	for _, f := range obs.Facts {
		if (f.Name == "product-serial" || f.Name == "product-uuid") && hostadoption.IdentityDigest(f.Name, f.Value) == draft.Request.NewIdentityDigest {
			if out.DestinationIdentityKind != "" {
				return deny()
			}
			out.DestinationIdentityKind = f.Name
		}
	}
	if out.DestinationIdentityKind == "" {
		return deny()
	}
	return out, nil
}
func validateRecoveryReceiveDraft(ctx context.Context, tx ReadTx, r generated.HostActionRequest) error {
	var input generated.ControlRecoveryReceiveInput
	if generated.ValidateContractJSON(generated.SchemaIDControlRecoveryReceiveInput, []byte(r.ActionInput), generated.ContractExact) != nil || json.Unmarshal([]byte(r.ActionInput), &input) != nil {
		return actionError(generated.ErrorCodeInputInvalid)
	}
	current, err := recoveryReceivePreparation(ctx, tx, input.Binding)
	if err != nil {
		return err
	}
	current.CandidateBytes = input.CandidateBytes
	current.CandidateBytesDigest = input.CandidateBytesDigest
	current.JournalBytes = input.JournalBytes
	if hostaction.Digest(current) != hostaction.Digest(input) || r.HostID != current.Replacement.NewHostID || r.ConsoleConfirmation.HostIdentityDigest != current.Replacement.NewIdentityDigest || r.TargetDigest != current.Replacement.NewTargetDigest || r.TargetRevision != current.Replacement.NewTargetRevision {
		return actionError(generated.ErrorCodePlanStale)
	}
	return nil
}

func authorizeRecoveryReceiveScope(ctx context.Context, row discoveryRow, p generated.Plan, runID, human string, r generated.HostActionRequest) error {
	var d generated.ControlRecoveryReceiveInput
	if json.Unmarshal([]byte(r.ActionInput), &d) != nil {
		return actionError(generated.ErrorCodeInputInvalid)
	}
	var actor string
	if row(`SELECT principal_id FROM audit_events WHERE event_type='run.created' AND correlation_id=? ORDER BY event_id LIMIT 1`, runID).Scan(&actor) != nil {
		return actionError(generated.ErrorCodeAuthorizationDenied)
	}
	for _, id := range []string{d.Replacement.OldHostID, d.Replacement.NewHostID} {
		if err := authorizeBaselinePrincipal(ctx, row, p, human, id, authorization.ActionAcknowledge, "plan.acknowledge", "plan-target"); err != nil {
			return err
		}
		if err := authorizeBaselinePrincipal(ctx, row, p, actor, id, authorization.ActionExecute, "host.action.execute", "execution-target"); err != nil {
			return err
		}
	}
	return nil
}

// Compare the complete existing bounded export, including unrelated aliases,
// within the caller's current read or writer transaction.
func validateRecoveryReceiveContinuity(ctx context.Context, tx ReadTx, b generated.RestoreBinding) error {
	if b.ReplacementContinuity == nil {
		return actionError(generated.ErrorCodePrerequisiteBlocked)
	}
	sealed := *b.ReplacementContinuity
	current, err := loadHostReplacementContinuity(ctx, tx, sealed.ReplacementID, sealed)
	if err != nil {
		return err
	}
	if current.Reference != sealed {
		return actionError(generated.ErrorCodePlanStale)
	}
	return nil
}
