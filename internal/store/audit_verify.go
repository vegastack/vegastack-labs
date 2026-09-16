package store

import (
	"context"
	"encoding/json"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

// VerifyAuditHistory validates local canonical events and chain links before it
// compares the newest anchored checkpoint with the independently scoped copy.
// An unavailable independent reader is degraded evidence; proven disagreement
// is an integrity incident and permanently disables mutations for this process.
func (store *Store) VerifyAuditHistory(ctx context.Context, independent adapter.CheckpointReader) (generated.AuditVerificationData, error) {
	store.mu.Lock()
	if err := store.readyForRead(ctx); err != nil {
		store.mu.Unlock()
		return generated.AuditVerificationData{}, err
	}
	links, events, checkpoints, instanceID, epoch, err := store.auditVerificationInputs(ctx)
	store.mu.Unlock()
	if err != nil {
		return generated.AuditVerificationData{}, err
	}

	local, verifyErr := audit.VerifyLocal(links, events, checkpoints)
	local.InstanceID, local.RecoveryEpoch, local.Namespace = instanceID, epoch, store.config.AuditCheckpointNamespace
	if verifyErr != nil {
		store.recordAuditIncident("audit-incident")
		return auditVerificationData(local, audit.VerificationResult{Status: "incident", ReasonCode: local.ReasonCode, LocalDigest: local.LocalDigest}), verifyErr
	}
	if local.LastAnchored == nil || independent == nil || len(store.config.AuditCheckpointPublicKey.Bytes) == 0 || store.config.AuditCheckpointNamespace == "" {
		return auditVerificationData(local, audit.VerificationResult{Status: local.Status, ReasonCode: local.ReasonCode, LocalDigest: local.LocalDigest, LastSequence: local.LastSequence, PreAnchor: local.PreAnchor}), nil
	}
	remote, readErr := independent.ReadLast(ctx, store.config.AuditCheckpointNamespace)
	if readErr != nil {
		result := audit.VerificationResult{Status: "degraded", ReasonCode: "independent-checkpoint-unavailable", LocalDigest: local.LocalDigest, LastSequence: local.LastSequence, PreAnchor: local.PreAnchor}
		return auditVerificationData(local, result), nil
	}
	result, compareErr := audit.CompareIndependent(local, remote, store.config.AuditCheckpointPublicKey)
	if compareErr != nil {
		store.recordAuditIncident("audit-incident")
	}
	return auditVerificationData(local, result), compareErr
}

func (store *Store) auditVerificationInputs(ctx context.Context) ([]audit.ChainLink, []audit.Event, []generated.AuditCheckpoint, string, int64, error) {
	var instanceID string
	var epoch int64
	if err := store.conn.QueryRowContext(ctx, `SELECT instance_id FROM audit_instances WHERE id=1`).Scan(&instanceID); err != nil {
		return nil, nil, nil, "", 0, store.transactionError(ctx, err)
	}
	if err := store.conn.QueryRowContext(ctx, `SELECT recovery_epoch FROM system_meta WHERE id=1`).Scan(&epoch); err != nil {
		return nil, nil, nil, "", 0, store.transactionError(ctx, err)
	}
	rows, err := store.conn.QueryContext(ctx, `SELECT canonical_payload FROM audit_events ORDER BY event_id`)
	if err != nil {
		return nil, nil, nil, "", 0, store.transactionError(ctx, err)
	}
	var events []audit.Event
	for rows.Next() {
		var raw []byte
		var event audit.Event
		if err := rows.Scan(&raw); err != nil {
			_ = rows.Close()
			return nil, nil, nil, "", 0, newStoreError("INTEGRITY_FAILURE", "audit-history", false, err)
		}
		if err := json.Unmarshal(raw, &event); err != nil {
			_ = rows.Close()
			return nil, nil, nil, "", 0, newStoreError("INTEGRITY_FAILURE", "audit-history", false, err)
		}
		events = append(events, event)
	}
	if err := rows.Close(); err != nil {
		return nil, nil, nil, "", 0, store.transactionError(ctx, err)
	}
	var links []audit.ChainLink
	if len(events) > 0 {
		rangeValue, err := store.ChainRange(ctx, audit.EventID(events[0].EventID), audit.EventID(events[len(events)-1].EventID))
		if err != nil {
			return nil, nil, nil, "", 0, err
		}
		links = rangeValue.Links
	}
	checkpointRows, err := store.conn.QueryContext(ctx, `SELECT canonical_bytes FROM audit_checkpoints ORDER BY last_event_id,checkpoint_id`)
	if err != nil {
		return nil, nil, nil, "", 0, store.transactionError(ctx, err)
	}
	var checkpoints []generated.AuditCheckpoint
	for checkpointRows.Next() {
		checkpoint, err := scanAuditCheckpoint(checkpointRows)
		if err != nil {
			_ = checkpointRows.Close()
			return nil, nil, nil, "", 0, err
		}
		checkpoints = append(checkpoints, checkpoint)
	}
	if err := checkpointRows.Close(); err != nil {
		return nil, nil, nil, "", 0, store.transactionError(ctx, err)
	}
	return links, events, checkpoints, instanceID, epoch, nil
}

func (store *Store) recordAuditIncident(reason string) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.enterSafeMode(reason)
}

func auditVerificationData(local audit.LocalResult, result audit.VerificationResult) generated.AuditVerificationData {
	data := generated.AuditVerificationData{
		Schema:               generated.SchemaIDAuditVerificationData,
		SchemaVersion:        "1.0.0",
		Status:               result.Status,
		InstanceID:           local.InstanceID,
		RecoveryEpoch:        local.RecoveryEpoch,
		LocalDigest:          string(result.LocalDigest),
		IndependentMatch:     result.IndependentMatch,
		LastAnchoredSequence: result.LastSequence,
		ReasonCode:           result.ReasonCode,
		PreAnchor:            result.PreAnchor,
	}
	if audit.ValidFingerprint(result.IndependentDigest) {
		value := string(result.IndependentDigest)
		data.IndependentDigest = &value
	}
	return data
}
