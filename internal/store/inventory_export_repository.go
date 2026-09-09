package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/inventory"
	"github.com/vegastack/vegastack-labs/internal/stateexport"
)

const exportTargetPrefix = "inventory-draft-export-r"

var exportTargetPattern = regexp.MustCompile(`^inventory-draft-export-r([1-9][0-9]*)$`)

type InventoryExportRepository struct {
	store *Store
}

func NewInventoryExportRepository(store *Store) *InventoryExportRepository {
	return &InventoryExportRepository{store: store}
}

func (repository *InventoryExportRepository) SnapshotInventoryDraft(ctx context.Context, ref inventory.DraftRef) (stateexport.DraftSnapshot, error) {
	if repository == nil || repository.store == nil || ref.ID == "" || ref.Revision < 1 {
		return stateexport.DraftSnapshot{}, newStoreError("INPUT_INVALID", "inventory-export-draft", false, nil)
	}
	var token RevisionToken
	var persisted inventory.PersistedDraft
	err := repository.store.Read(ctx, func(tx ReadTx) error {
		if err := tx.queryRow(ctx, `SELECT state_revision,recovery_epoch FROM system_meta WHERE id=1`).Scan(&token.StateRevision, &token.RecoveryEpoch); err != nil {
			return classifySQLiteError(ctx, err)
		}
		return NewInventoryDraftRepository(repository.store).readDraft(ctx, tx, ref, &persisted)
	})
	if err != nil {
		return stateexport.DraftSnapshot{}, err
	}
	return stateexport.DraftSnapshot{StateRevision: token.StateRevision, RecoveryEpoch: token.RecoveryEpoch, Draft: canonicalExportDraft(persisted)}, nil
}

func canonicalExportDraft(value inventory.PersistedDraft) inventory.CanonicalDraftSnapshot {
	assets := append([]inventory.DraftAsset{}, value.Assets...)
	for index := range assets {
		assets[index].Identities = append([]inventory.DraftIdentity{}, assets[index].Identities...)
		assets[index].HardwareFacts = append([]inventory.DraftHardwareFact{}, assets[index].HardwareFacts...)
	}
	findings := append([]inventory.Finding{}, value.Findings...)
	for index := range findings {
		findings[index].RelatedIDs = append([]inventory.LocalID{}, findings[index].RelatedIDs...)
	}
	return inventory.CanonicalDraftSnapshot{
		Kind: "draft", Ref: value.Ref, ValidationStatus: value.ValidationStatus, Source: value.Source,
		Assets: assets, Nodes: append([]inventory.DraftNode{}, value.Nodes...), Aliases: append([]inventory.DraftAlias{}, value.Aliases...),
		Addresses: append([]inventory.DraftAddress{}, value.Addresses...), Observations: append([]inventory.DraftObservation{}, value.Observations...),
		Provenance: append([]inventory.FieldProvenance{}, value.Provenance...), Findings: findings, ContentDigest: value.ContentDigest,
	}
}

func (repository *InventoryExportRepository) AppendExportAudit(ctx context.Context, request stateexport.AuditAppendRequest) (stateexport.AuditAppendResult, error) {
	if repository == nil || repository.store == nil || request.ExpectedStateRevision < 0 || request.ExpectedRecoveryEpoch < 0 ||
		audit.ValidateIntentKey(request.Idempotency) != nil || audit.ValidateEventDraft(request.Event) != nil ||
		audit.ValidateOutboxRequirements(request.Destinations) != nil || !validExportEvent(request.Event) {
		return stateexport.AuditAppendResult{}, newStoreError("INPUT_INVALID", "inventory-export-audit", false, nil)
	}
	replay, err := repository.exactReplay(ctx, request.Idempotency)
	if err != nil {
		return stateexport.AuditAppendResult{}, err
	}
	if !replay && request.Event.Type != "inventory.export.requested" {
		if err := repository.validateTerminal(ctx, request.Event); err != nil {
			return stateexport.AuditAppendResult{}, err
		}
	}
	result, err := repository.store.AppendOperationalAudit(ctx, OperationalAuditRequest{
		Expected:    RevisionToken{StateRevision: request.ExpectedStateRevision, RecoveryEpoch: request.ExpectedRecoveryEpoch},
		Idempotency: request.Idempotency, Event: request.Event, Destinations: request.Destinations,
	})
	if err != nil {
		return stateexport.AuditAppendResult{}, err
	}
	return stateexport.AuditAppendResult{EventID: result.EventID, StateRevision: result.StateRevision, RecoveryEpoch: result.RecoveryEpoch, Created: result.Created}, nil
}

func (repository *InventoryExportRepository) exactReplay(ctx context.Context, key audit.IntentKey) (bool, error) {
	var digest string
	err := repository.store.Read(ctx, func(tx ReadTx) error {
		return tx.queryRow(ctx, `SELECT request_digest FROM intent_keys WHERE scope=? AND key_digest=?`, key.Scope, key.KeyDigest).Scan(&digest)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if digest != string(key.RequestDigest) {
		return false, newStoreError("STATE_CONFLICT", "inventory-export-audit-key", false, nil)
	}
	return true, nil
}

func (repository *InventoryExportRepository) validateTerminal(ctx context.Context, terminal audit.EventDraft) error {
	if terminal.CausationID == nil {
		return newStoreError("INPUT_INVALID", "inventory-export-audit", false, nil)
	}
	var eventType, correlation, targetKind, targetID string
	var before, after sql.NullString
	var terminalCount int
	err := repository.store.Read(ctx, func(tx ReadTx) error {
		if err := tx.queryRow(ctx, `SELECT event_type,correlation_id,target_kind,target_id,before_fingerprint,after_fingerprint FROM audit_events WHERE event_id=?`, *terminal.CausationID).Scan(&eventType, &correlation, &targetKind, &targetID, &before, &after); err != nil {
			return err
		}
		return tx.queryRow(ctx, `SELECT COUNT(*) FROM audit_events WHERE causation_event_id=? AND event_type IN ('inventory.export.published','inventory.export.failed','inventory.export.interrupted')`, *terminal.CausationID).Scan(&terminalCount)
	})
	if err != nil {
		return newStoreError("STATE_CONFLICT", "inventory-export-causation", false, nil)
	}
	if eventType != "inventory.export.requested" || terminalCount != 0 || terminal.CorrelationID != correlation ||
		string(terminal.Target.Kind) != targetKind || terminal.Target.ID != targetID || !sameOptionalFingerprint(terminal.Before, before) || !sameOptionalFingerprint(terminal.After, after) {
		return newStoreError("STATE_CONFLICT", "inventory-export-causation", false, nil)
	}
	return nil
}

func sameOptionalFingerprint(value *audit.Fingerprint, stored sql.NullString) bool {
	if value == nil {
		return !stored.Valid
	}
	return stored.Valid && string(*value) == stored.String
}

func validExportEvent(event audit.EventDraft) bool {
	revision, ok := exportTargetRevision(event.Target.Kind)
	if !ok || revision < 1 || event.Target.ID == "" || event.After == nil || !audit.ValidFingerprint(*event.After) || (event.Before != nil && !audit.ValidFingerprint(*event.Before)) || event.CorrectionOf != nil {
		return false
	}
	switch event.Type {
	case "inventory.export.requested":
		return event.CausationID == nil
	case "inventory.export.published", "inventory.export.failed", "inventory.export.interrupted":
		return event.CausationID != nil
	default:
		return false
	}
}

func exportTargetRevision(kind audit.TargetKind) (int64, bool) {
	match := exportTargetPattern.FindStringSubmatch(string(kind))
	if len(match) != 2 {
		return 0, false
	}
	revision, err := strconv.ParseInt(match[1], 10, 64)
	return revision, err == nil && revision > 0
}

func ExportTarget(ref inventory.DraftRef) (audit.Target, error) {
	if ref.ID == "" || ref.Revision < 1 {
		return audit.Target{}, newStoreError("INPUT_INVALID", "inventory-export-draft", false, nil)
	}
	target := audit.Target{Kind: audit.TargetKind(fmt.Sprintf("%s%d", exportTargetPrefix, ref.Revision)), ID: string(ref.ID)}
	if len(target.Kind) > 64 || audit.ValidateEventDraft(audit.EventDraft{
		Type: "inventory.export.requested", CorrelationID: "validation", Attribution: audit.Attribution{AuthenticatedPrincipalID: "validation", AuthenticatedPrincipalMethod: "local-os-peer"},
		Target: target, After: func() *audit.Fingerprint {
			value := audit.Fingerprint("sha256:" + strings.Repeat("0", 64))
			return &value
		}(),
	}) != nil {
		return audit.Target{}, newStoreError("INPUT_INVALID", "inventory-export-draft", false, nil)
	}
	return target, nil
}

func (repository *InventoryExportRepository) PendingExportRequests(ctx context.Context, limit int) ([]stateexport.PendingExportRequest, error) {
	if repository == nil || repository.store == nil || limit < 1 || limit > 64 {
		return nil, newStoreError("INPUT_INVALID", "inventory-export-pending", false, nil)
	}
	result := make([]stateexport.PendingExportRequest, 0)
	err := repository.store.Read(ctx, func(tx ReadTx) error {
		rows, err := tx.query(ctx, `SELECT r.event_id,r.correlation_id,r.principal_id,r.principal_method,r.responsible_human_principal_id,r.agent_name,r.agent_session_id,r.target_kind,r.target_id,r.state_revision,r.recovery_epoch,r.before_fingerprint,r.after_fingerprint
			FROM audit_events r
			WHERE r.event_type='inventory.export.requested'
			AND NOT EXISTS (SELECT 1 FROM audit_events t WHERE t.causation_event_id=r.event_id AND t.event_type IN ('inventory.export.published','inventory.export.failed','inventory.export.interrupted'))
			ORDER BY r.event_id LIMIT ?`, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var pending stateexport.PendingExportRequest
			var principalID, principalMethod, targetKind, targetID string
			var human, agentName, agentSession, before sql.NullString
			var after string
			if err := rows.Scan(&pending.EventID, &pending.CorrelationID, &principalID, &principalMethod, &human, &agentName, &agentSession, &targetKind, &targetID, &pending.StateRevision, &pending.RecoveryEpoch, &before, &after); err != nil {
				return err
			}
			revision, ok := exportTargetRevision(audit.TargetKind(targetKind))
			if !ok || !audit.ValidFingerprint(audit.Fingerprint(after)) {
				return newStoreError("INTEGRITY_FAILURE", "inventory-export-pending", false, nil)
			}
			pending.Draft = inventory.DraftRef{ID: inventory.DraftID(targetID), Revision: revision}
			pending.ExportID = after
			pending.RequestedDigest = audit.Fingerprint(after)
			pending.Attribution = audit.Attribution{AuthenticatedPrincipalID: principalID, AuthenticatedPrincipalMethod: principalMethod}
			if human.Valid {
				value := human.String
				pending.Attribution.ResponsibleHumanPrincipalID = &value
			}
			if agentName.Valid != agentSession.Valid {
				return newStoreError("INTEGRITY_FAILURE", "inventory-export-pending", false, nil)
			}
			if agentName.Valid {
				pending.Attribution.Agent = &audit.AgentMetadata{Name: agentName.String, SessionID: agentSession.String}
			}
			if before.Valid {
				value := audit.Fingerprint(before.String)
				if !audit.ValidFingerprint(value) {
					return newStoreError("INTEGRITY_FAILURE", "inventory-export-pending", false, nil)
				}
				pending.PreviousDigest = &value
			}
			result = append(result, pending)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

var _ stateexport.SnapshotSource = (*InventoryExportRepository)(nil)
var _ stateexport.AuditRepository = (*InventoryExportRepository)(nil)
