package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/hostreplacement"
	"github.com/vegastack/vegastack-labs/internal/linuxrole"
	"time"
)

type HostReplacementRepository struct {
	store *Store
	gates *GateRepository
}

func NewHostReplacementRepository(s *Store) *HostReplacementRepository {
	return &HostReplacementRepository{store: s, gates: NewGateRepository(s)}
}

type HostReplacementDraft struct {
	ID, Digest, BindingDigest string
	Request                   generated.HostReplacementRequest
}
type HostReplacementExecution struct {
	ReplacementID, DraftID, PlanID, PlanDigest, RunID, StepID, LeaseID string
	Attribution                                                        audit.Attribution
}
type HostReplacementEvent struct {
	ReplacementID     string
	Sequence          int64
	Type              string
	Execution         HostReplacementExecution
	State             generated.HostReplacementState
	AuthorityDigest   string
	OutstandingDigest string
	Challenge         []byte
	FenceReceipt      []byte
	At                string
}

func replacementError(code string) error { return newStoreError(code, "host-replacement", false, nil) }
func readReplacementDraft(row discoveryRow, id string) (d HostReplacementDraft, err error) {
	var raw []byte
	d.ID = id
	err = row(`SELECT content_digest,binding_digest,request_bytes FROM host_replacement_drafts WHERE draft_id=?`, id).Scan(&d.Digest, &d.BindingDigest, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return d, replacementError(generated.ErrorCodeResourceNotFound)
	}
	if err != nil {
		return d, err
	}
	if json.Unmarshal(raw, &d.Request) != nil || hostaction.Digest(d.Request) != d.Digest {
		return d, replacementError(generated.ErrorCodeIntegrityFailure)
	}
	return d, nil
}
func (r *HostReplacementRepository) GetDraft(ctx context.Context, id string) (d HostReplacementDraft, err error) {
	err = r.store.Read(ctx, func(tx ReadTx) error {
		var e error
		row := func(q string, a ...any) *sql.Row { return tx.queryRow(ctx, q, a...) }
		d, e = readReplacementDraft(row, id)
		if e == nil {
			e = validateReplacementDraftBinding(row, d)
		}
		if e != nil {
			return e
		}
		for _, host := range []string{d.Request.OldHostID, d.Request.NewHostID} {
			if _, e = adoptionGrant(ctx, row, host, "host", "read", "host.read", false); e != nil {
				return e
			}
		}
		return nil
	})
	return
}
func replacementHost(row discoveryRow, id, identity, targetDigest, keyDigest string, revision int64, profile string) error {
	h, err := readManagedHost(row, id)
	if err != nil {
		return err
	}
	var currentIdentity string
	if row(`SELECT identity_digest FROM managed_hosts WHERE host_id=?`, id).Scan(&currentIdentity) != nil || currentIdentity != identity || h.ProfileID != profile {
		return replacementError(generated.ErrorCodePlanStale)
	}
	target, err := discoveryTarget(row, h.TargetID)
	if err != nil {
		return err
	}
	key, err := hostreplacement.SSHHostKeyDigest(target.Binding.HostKey)
	if err != nil || key != keyDigest || target.Digest != targetDigest || target.Binding.Revision != revision {
		return replacementError(generated.ErrorCodePlanStale)
	}
	return nil
}
func validateReplacementHosts(row discoveryRow, q generated.HostReplacementRequest) error {
	if q.OldHostID == q.NewHostID || q.OldIdentityDigest == q.NewIdentityDigest || q.OldSSHHostKeyDigest == q.NewSSHHostKeyDigest {
		return replacementError(generated.ErrorCodeInputInvalid)
	}
	if err := replacementHost(row, q.OldHostID, q.OldIdentityDigest, q.OldTargetDigest, q.OldSSHHostKeyDigest, q.OldTargetRevision, q.ProfileID); err != nil {
		return err
	}
	if err := replacementHost(row, q.NewHostID, q.NewIdentityDigest, q.NewTargetDigest, q.NewSSHHostKeyDigest, q.NewTargetRevision, q.ProfileID); err != nil {
		return err
	}
	obs, err := readDiscoveryObservation(row, q.OSPreparation.ObservationID)
	if err != nil || obs.ContentDigest != q.OSPreparation.ObservationDigest || obs.TargetDigest != q.NewTargetDigest || obs.TargetRevision != q.NewTargetRevision || q.OSPreparation.HostIdentityDigest != q.NewIdentityDigest {
		return replacementError(generated.ErrorCodePlanStale)
	}
	oldHost, e := readManagedHost(row, q.OldHostID)
	if e != nil {
		return e
	}
	oldObservation, e := readDiscoveryObservation(row, oldHost.ObservationID)
	if e != nil {
		return e
	}
	for _, prior := range oldObservation.Facts {
		if prior.Name != "machine-id" && prior.Name != "product-serial" && prior.Name != "product-uuid" {
			continue
		}
		for _, fresh := range obs.Facts {
			if fresh.Name == prior.Name && prior.Value != "" && fresh.Value == prior.Value {
				return replacementError(generated.ErrorCodeInputInvalid)
			}
		}
	}
	// Both declaration revision and actual prior execution intent are exact.
	var declared []byte
	var declaration generated.DeclarationRevision
	if row(`SELECT canonical_bytes FROM declaration_revisions WHERE declaration_id=? AND declaration_revision=?`, q.ProposedRoleDeclarationID, q.ProposedRoleDeclarationRevision).Scan(&declared) != nil || json.Unmarshal(declared, &declaration) != nil || declaration.DeclarationID != q.ProposedRoleDeclarationID || declaration.Revision != q.ProposedRoleDeclarationRevision {
		return replacementError(generated.ErrorCodePlanStale)
	}
	if q.Operation == "freeze" {
		var prior []byte
		var p generated.Plan
		if row(`SELECT p.canonical_bytes FROM immutable_plans p JOIN plan_runs r ON r.plan_id=p.plan_id AND r.plan_digest=p.plan_digest JOIN plan_run_steps s ON s.run_id=r.run_id WHERE s.target_id=? AND s.effect_state IN ('intent-recorded','receipt-recorded','effect-unknown','verified') AND json_extract(p.canonical_bytes,'$.hostAction.actionId') IN ('debian.role.apply','debian.control.handoff') ORDER BY p.state_revision DESC,p.plan_id DESC LIMIT 1`, q.OldHostID).Scan(&prior) != nil || json.Unmarshal(prior, &p) != nil || p.HostRoleScope == nil || p.DeclarationID != q.RoleDeclarationID || p.Binding.DeclarationRevision != q.RoleDeclarationRevision || p.HostRoleScope.RoleBindingDigest != q.OldRoleBindingDigest || p.HostRoleScope.ProfileLockDigest != q.ProfileLockDigest || p.HostRoleScope.SubjectIdentityDigest != q.OldIdentityDigest {
			return replacementError(generated.ErrorCodePlanStale)
		}
	}
	// Exact proposed role declaration is an existing ordinary role action draft.
	d, err := readHostActionDraft(row, q.ProposedRoleDeclarationID)
	if err != nil {
		return err
	}
	in, err := linuxrole.DecodeInput([]byte(d.Request.ActionInput))
	if err != nil || in.HostID != q.NewHostID || in.HostIdentityDigest != q.NewIdentityDigest || in.RoleBindingDigest != q.ProposedRoleBindingDigest || in.ProfileLockDigest != q.ProfileLockDigest || hostreplacement.RolePreimageDigest(in) != q.PreservedPreimageDigest {
		return replacementError(generated.ErrorCodePlanStale)
	}
	return nil
}
func (r *HostReplacementRepository) Stage(ctx context.Context, q generated.HostReplacementRequest, a audit.Attribution) (HostReplacementDraft, error) {
	if r == nil || r.store == nil || hostreplacement.ValidateInput(q) != nil {
		return HostReplacementDraft{}, replacementError(generated.ErrorCodeInputInvalid)
	}
	if q.Operation == "freeze" && q.ExpectedDeclarationRevision != 0 {
		return HostReplacementDraft{}, replacementError(generated.ErrorCodePlanStale)
	}
	d := HostReplacementDraft{Request: q, Digest: hostaction.Digest(q), BindingDigest: hostreplacement.BindingDigest(q)}
	d.ID = "host-replacement-" + d.Digest[7:39]
	raw, _ := json.Marshal(q)
	intent := discoveryIntent(a, "host.replacement.drafted", q.ReplacementID, hostaction.Digest(q.IdempotencyKey), d.Digest)
	intent.Expected = &RevisionToken{StateRevision: q.ExpectedStateRevision, RecoveryEpoch: q.RecoveryEpoch}
	_, err := r.store.executeAuditIntent(ctx, intent, false, func(ctx context.Context, tx *sql.Tx) error {
		row := func(q string, a ...any) *sql.Row { return tx.QueryRowContext(ctx, q, a...) }
		for _, id := range []string{q.OldHostID, q.NewHostID} {
			actor, e := adoptionGrant(ctx, row, id, "host", "author", "host.replacement.prepare", true)
			if e != nil {
				return e
			}
			if actor != a.AuthenticatedPrincipalID {
				return replacementError(generated.ErrorCodeAuthorizationDenied)
			}
		}
		if err := validateReplacementHosts(row, q); err != nil {
			return err
		}
		if err := r.validateReplacementOwnedScope(ctx, ReadTx{handle: tx}, q); err != nil {
			return err
		}
		var previous string
		err := row(`SELECT binding_digest FROM host_replacement_drafts WHERE replacement_id=? AND operation='freeze'`, q.ReplacementID).Scan(&previous)
		if q.Operation == "commit" {
			frozen, _, e := readReplacementEvent(row, q.ReplacementID)
			if e != nil || q.ExpectedDeclarationRevision != frozen.State.DeclarationRevision {
				return replacementError(generated.ErrorCodePlanStale)
			}
			if err != nil {
				return replacementError(generated.ErrorCodePlanStale)
			}
			if previous != d.BindingDigest {
				var oldID string
				if row(`SELECT draft_id FROM host_replacement_drafts WHERE replacement_id=? AND operation='freeze'`, q.ReplacementID).Scan(&oldID) != nil {
					return replacementError(generated.ErrorCodePlanStale)
				}
				old, e := readReplacementDraft(row, oldID)
				if e != nil {
					return e
				}
				if _, e = verifiedReplacementRestore(row, old.Request, q.RecoveryEpoch); e != nil {
					return e
				}
				normalized := q
				normalized.RecoveryEpoch = old.Request.RecoveryEpoch
				if hostreplacement.BindingDigest(normalized) != previous {
					return replacementError(generated.ErrorCodePlanStale)
				}
				d.BindingDigest = previous
			}
		} else if !errors.Is(err, sql.ErrNoRows) {
			return replacementError(generated.ErrorCodeStateConflict)
		}
		for _, alias := range q.AliasBindings {
			if err := validateAliasOwner(row, alias, q.Operation == "commit", q.ReplacementID); err != nil {
				return err
			}
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO host_replacement_drafts VALUES(?,?,?,?,?,?,?,?,?)`, d.ID, q.ReplacementID, q.Operation, d.BindingDigest, d.Digest, raw, a.AuthenticatedPrincipalID, q.ExpectedStateRevision, q.RecoveryEpoch)
		return err
	})
	if err != nil {
		return d, err
	}
	return r.GetDraft(ctx, d.ID)
}
func validateAliasOwner(row discoveryRow, a generated.HostReplacementAliasBinding, frozen bool, replacementID string) error {
	expectedRevision := a.OwnerRevision
	if frozen {
		expectedRevision++
	}
	var host, identity string
	var revision, generation int64
	var freeze sql.NullString
	if row(`SELECT owner_host_id,owner_identity_digest,owner_revision,ownership_generation,frozen_replacement_id FROM host_alias_owners WHERE alias_id=?`, a.AliasID).Scan(&host, &identity, &revision, &generation, &freeze) != nil || host != a.OwnerHostID || identity != a.OwnerIdentityDigest || revision != expectedRevision || generation != a.OwnershipGeneration || frozen && (!freeze.Valid || freeze.String != replacementID) || !frozen && freeze.Valid {
		return replacementError(generated.ErrorCodePlanStale)
	}
	return nil
}
func replacementState(d HostReplacementDraft) generated.HostReplacementState {
	q := d.Request
	generation := q.AliasBindings[0].OwnershipGeneration
	return generated.HostReplacementState{Schema: generated.SchemaIDHostReplacementState, SchemaVersion: "1.0.0", ReplacementID: q.ReplacementID, DeclarationID: d.ID, DeclarationRevision: 1, OldHostID: q.OldHostID, NewHostID: q.NewHostID, OldIdentityDigest: q.OldIdentityDigest, NewIdentityDigest: q.NewIdentityDigest, BindingDigest: d.BindingDigest, RoleBindingDigest: q.ProposedRoleBindingDigest, PriorOwnershipGeneration: generation, ProposedOwnershipGeneration: generation + 1, AliasBindings: q.AliasBindings, StateRevision: q.ExpectedStateRevision, RecoveryEpoch: q.RecoveryEpoch, Status: "staged", RestorationClass: q.RestorationClass, NextAction: "approve-freeze", Blockers: []string{}}
}
func readReplacementEvent(row discoveryRow, id string) (e HostReplacementEvent, digest string, err error) {
	var raw []byte
	err = row(`SELECT event_bytes,event_digest FROM host_replacement_events WHERE replacement_id=? ORDER BY sequence DESC LIMIT 1`, id).Scan(&raw, &digest)
	if err != nil {
		return
	}
	if json.Unmarshal(raw, &e) != nil || hostaction.Digest(e) != digest {
		err = replacementError(generated.ErrorCodeIntegrityFailure)
	}
	return
}
func (r *HostReplacementRepository) Get(ctx context.Context, id string) (out generated.HostReplacementState, err error) {
	err = r.store.Read(ctx, func(tx ReadTx) error {
		row := func(q string, a ...any) *sql.Row { return tx.queryRow(ctx, q, a...) }
		var draftID string
		if err := row(`SELECT draft_id FROM host_replacement_drafts WHERE replacement_id=? AND operation='freeze'`, id).Scan(&draftID); err != nil {
			return replacementError(generated.ErrorCodeResourceNotFound)
		}
		d, e := readReplacementDraft(row, draftID)
		if e != nil {
			return e
		}
		for _, host := range []string{d.Request.OldHostID, d.Request.NewHostID} {
			if _, e = adoptionGrant(ctx, row, host, "host", "read", "host.read", false); e != nil {
				return e
			}
		}
		event, _, e := readReplacementEvent(row, id)
		if errors.Is(e, sql.ErrNoRows) {
			out = replacementState(d)
			return nil
		}
		if e != nil {
			return e
		}
		out = event.State
		if out.FreezeEventDigest == "" {
			_ = row(`SELECT event_digest FROM host_replacement_events WHERE replacement_id=? AND event_type='frozen'`, id).Scan(&out.FreezeEventDigest)
		}
		return nil
	})
	return
}
func insertReplacementEvent(ctx context.Context, tx *sql.Tx, e HostReplacementEvent) (string, error) {
	raw, err := json.Marshal(e)
	if err != nil || len(raw) > 1048576 {
		return "", replacementError(generated.ErrorCodeInputInvalid)
	}
	digest := hostaction.Digest(e)
	_, err = tx.ExecContext(ctx, `INSERT INTO host_replacement_events VALUES(?,?,?,?,?,?,?,?,?,?,?)`, e.ReplacementID, e.Sequence, e.Type, e.State.OldHostID, e.State.OldIdentityDigest, e.State.NewHostID, e.State.NewIdentityDigest, digest, raw, e.State.StateRevision, e.State.RecoveryEpoch)
	return digest, err
}
func replacementNow(s *Store) string {
	return s.config.Clock().UTC().Truncate(time.Second).Format(time.RFC3339)
}

// ConfigureAdmission uses the same scoped proof reader as the server evaluator.
func (r *HostReplacementRepository) ConfigureAdmission(g *GateRepository) error {
	if g == nil || g.store != r.store {
		return replacementError(generated.ErrorCodeInputInvalid)
	}
	r.gates = g
	return nil
}

func validateReplacementDraftBinding(row discoveryRow, d HostReplacementDraft) error {
	if hostreplacement.BindingDigest(d.Request) == d.BindingDigest {
		return nil
	}
	if d.Request.Operation != "commit" || d.Request.RestorationClass != "control-database" {
		return replacementError(generated.ErrorCodeIntegrityFailure)
	}
	var id string
	if row(`SELECT draft_id FROM host_replacement_drafts WHERE replacement_id=? AND operation='freeze'`, d.Request.ReplacementID).Scan(&id) != nil {
		return replacementError(generated.ErrorCodeIntegrityFailure)
	}
	original, e := readReplacementDraft(row, id)
	if e != nil {
		return e
	}
	if _, e = verifiedReplacementRestore(row, original.Request, d.Request.RecoveryEpoch); e != nil {
		return e
	}
	normalized := d.Request
	normalized.RecoveryEpoch = original.Request.RecoveryEpoch
	if hostreplacement.BindingDigest(normalized) != d.BindingDigest || original.BindingDigest != d.BindingDigest {
		return replacementError(generated.ErrorCodeIntegrityFailure)
	}
	return nil
}
func (r *HostReplacementRepository) ValidateDraftBinding(ctx context.Context, d HostReplacementDraft) error {
	return r.store.Read(ctx, func(tx ReadTx) error {
		return validateReplacementDraftBinding(func(q string, a ...any) *sql.Row { return tx.queryRow(ctx, q, a...) }, d)
	})
}
