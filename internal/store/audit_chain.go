package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/vegastack/vegastack-labs/internal/audit"
)

const emptyAuditBinding = audit.Fingerprint("sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

type BackfillResult struct {
	Added int
}

func (store *Store) appendAuditLink(ctx context.Context, tx *sql.Tx, event audit.Event, ids audit.ContextIDs) (audit.ChainLink, error) {
	var instanceID string
	if err := tx.QueryRowContext(ctx, `SELECT instance_id FROM system_meta WHERE id=1`).Scan(&instanceID); err != nil {
		return audit.ChainLink{}, store.transactionError(ctx, err)
	}
	previous, sequence, err := ensureAuditGenesis(ctx, tx, instanceID, event.RecoveryEpoch, false)
	if err != nil {
		return audit.ChainLink{}, store.transactionError(ctx, err)
	}
	var lastDigest audit.Fingerprint
	var lastSequence int64
	err = tx.QueryRowContext(ctx, `SELECT link_digest,segment_sequence FROM audit_chain_links WHERE recovery_epoch=? ORDER BY segment_sequence DESC LIMIT 1`, event.RecoveryEpoch).Scan(&lastDigest, &lastSequence)
	switch {
	case err == nil:
		previous, sequence = lastDigest, lastSequence+1
	case !errors.Is(err, sql.ErrNoRows):
		return audit.ChainLink{}, store.transactionError(ctx, err)
	}
	link, err := audit.MakeChainLink(event, ids, instanceID, sequence, previous, false)
	if err != nil {
		return audit.ChainLink{}, newStoreError("INTEGRITY_FAILURE", "audit-chain-link", false, err)
	}
	contextBytes, contextDigest, err := audit.CanonicalContext(ids)
	if err != nil || contextDigest != link.ContextDigest {
		return audit.ChainLink{}, newStoreError("INTEGRITY_FAILURE", "audit-chain-context", false, err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_chain_links(event_id,instance_id,recovery_epoch,segment_sequence,previous_digest,payload_digest,context_bytes,context_digest,link_digest,pre_anchor) VALUES(?,?,?,?,?,?,?,?,?,0)`, link.EventID, link.InstanceID, link.RecoveryEpoch, link.SegmentSequence, link.PreviousDigest, link.PayloadDigest, contextBytes, link.ContextDigest, link.LinkDigest); err != nil {
		return audit.ChainLink{}, store.transactionError(ctx, err)
	}
	return link, nil
}

func ensureAuditGenesis(ctx context.Context, tx *sql.Tx, instanceID string, epoch int64, allowLegacyPreAnchor bool) (audit.Fingerprint, int64, error) {
	var digest audit.Fingerprint
	err := tx.QueryRowContext(ctx, `SELECT genesis_digest FROM audit_epoch_genesis WHERE recovery_epoch=?`, epoch).Scan(&digest)
	if err == nil {
		return digest, 1, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", 0, err
	}
	if epoch > 0 && !allowLegacyPreAnchor {
		return "", 0, errors.New("recovery audit genesis is not bound")
	}
	genesis := audit.GenesisLink(instanceID, epoch, emptyAuditBinding, emptyAuditBinding)
	if !audit.ValidFingerprint(genesis.LinkDigest) {
		return "", 0, errors.New("invalid audit genesis")
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_epoch_genesis(recovery_epoch,instance_id,prior_checkpoint_digest,recovery_decision_digest,genesis_digest) VALUES(?,?,?,?,?)`, epoch, instanceID, genesis.PriorCheckpoint, genesis.RecoveryDecision, genesis.LinkDigest); err != nil {
		return "", 0, err
	}
	return genesis.LinkDigest, 1, nil
}

func (store *Store) backfillPreAnchor(ctx context.Context) (BackfillResult, error) {
	tx, err := store.conn.BeginTx(ctx, nil)
	if err != nil {
		return BackfillResult{}, store.transactionError(ctx, err)
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(ctx, `SELECT e.canonical_payload,e.payload_sha256 FROM audit_events e LEFT JOIN audit_chain_links l ON l.event_id=e.event_id WHERE l.event_id IS NULL ORDER BY e.event_id`)
	if err != nil {
		return BackfillResult{}, store.transactionError(ctx, err)
	}
	type legacy struct {
		payload []byte
		digest  audit.Fingerprint
	}
	var pending []legacy
	for rows.Next() {
		var row legacy
		if err := rows.Scan(&row.payload, &row.digest); err != nil {
			_ = rows.Close()
			return BackfillResult{}, store.transactionError(ctx, err)
		}
		pending = append(pending, row)
	}
	if err := rows.Close(); err != nil {
		return BackfillResult{}, store.transactionError(ctx, err)
	}
	var instanceID string
	if err := tx.QueryRowContext(ctx, `SELECT instance_id FROM system_meta WHERE id=1`).Scan(&instanceID); err != nil {
		return BackfillResult{}, store.transactionError(ctx, err)
	}
	result := BackfillResult{}
	for _, row := range pending {
		sum := sha256.Sum256(row.payload)
		if audit.Fingerprint("sha256:"+hex.EncodeToString(sum[:])) != row.digest {
			return BackfillResult{}, newStoreError("INTEGRITY_FAILURE", "audit-chain-backfill", false, nil)
		}
		var event audit.Event
		if err := json.Unmarshal(row.payload, &event); err != nil {
			return BackfillResult{}, newStoreError("INTEGRITY_FAILURE", "audit-chain-backfill", false, nil)
		}
		canonical, digest, err := audit.CanonicalEvent(event)
		if err != nil || string(canonical) != string(row.payload) || digest != row.digest {
			return BackfillResult{}, newStoreError("INTEGRITY_FAILURE", "audit-chain-backfill", false, err)
		}
		previous, sequence, err := ensureAuditGenesis(ctx, tx, instanceID, event.RecoveryEpoch, true)
		if err != nil {
			return BackfillResult{}, store.transactionError(ctx, err)
		}
		var lastDigest audit.Fingerprint
		var lastSequence int64
		err = tx.QueryRowContext(ctx, `SELECT link_digest,segment_sequence FROM audit_chain_links WHERE recovery_epoch=? ORDER BY segment_sequence DESC LIMIT 1`, event.RecoveryEpoch).Scan(&lastDigest, &lastSequence)
		if err == nil {
			previous, sequence = lastDigest, lastSequence+1
		} else if !errors.Is(err, sql.ErrNoRows) {
			return BackfillResult{}, store.transactionError(ctx, err)
		}
		link, err := audit.MakeChainLink(event, audit.ContextIDs{}, instanceID, sequence, previous, true)
		if err != nil {
			return BackfillResult{}, newStoreError("INTEGRITY_FAILURE", "audit-chain-backfill", false, err)
		}
		contextBytes, _, _ := audit.CanonicalContext(audit.ContextIDs{})
		if _, err := tx.ExecContext(ctx, `INSERT INTO audit_chain_links(event_id,instance_id,recovery_epoch,segment_sequence,previous_digest,payload_digest,context_bytes,context_digest,link_digest,pre_anchor) VALUES(?,?,?,?,?,?,?,?,?,1)`, link.EventID, link.InstanceID, link.RecoveryEpoch, link.SegmentSequence, link.PreviousDigest, link.PayloadDigest, contextBytes, link.ContextDigest, link.LinkDigest); err != nil {
			return BackfillResult{}, store.transactionError(ctx, err)
		}
		result.Added++
	}
	if err := tx.Commit(); err != nil {
		return BackfillResult{}, store.transactionError(ctx, err)
	}
	return result, nil
}

// PrepareRecoveryAuditEpoch binds the next epoch to the independently known
// prior checkpoint and the approved recovery decision before any restored
// authority can append a new event. The recovery workflow remains responsible
// for advancing system_meta only after its other fencing checks pass.
func (store *Store) PrepareRecoveryAuditEpoch(ctx context.Context, epoch int64, priorCheckpoint, recoveryDecision audit.Fingerprint) error {
	if epoch <= 0 || !audit.ValidFingerprint(priorCheckpoint) || !audit.ValidFingerprint(recoveryDecision) {
		return newStoreError("INPUT_INVALID", "audit-recovery-genesis", false, nil)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.readyForRead(ctx); err != nil {
		return err
	}
	tx, err := store.conn.BeginTx(ctx, nil)
	if err != nil {
		return store.transactionError(ctx, err)
	}
	defer func() { _ = tx.Rollback() }()
	var instanceID string
	var currentEpoch int64
	if err := tx.QueryRowContext(ctx, `SELECT instance_id FROM system_meta WHERE id=1`).Scan(&instanceID); err != nil {
		return store.transactionError(ctx, err)
	}
	if err := tx.QueryRowContext(ctx, `SELECT recovery_epoch FROM system_meta WHERE id=1`).Scan(&currentEpoch); err != nil {
		return store.transactionError(ctx, err)
	}
	if epoch != currentEpoch+1 {
		return newStoreError("STATE_CONFLICT", "audit-recovery-genesis", false, nil)
	}
	genesis := audit.GenesisLink(instanceID, epoch, priorCheckpoint, recoveryDecision)
	if !audit.ValidFingerprint(genesis.LinkDigest) {
		return newStoreError("INPUT_INVALID", "audit-recovery-genesis", false, nil)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_epoch_genesis(recovery_epoch,instance_id,prior_checkpoint_digest,recovery_decision_digest,genesis_digest) VALUES(?,?,?,?,?)`, epoch, instanceID, priorCheckpoint, recoveryDecision, genesis.LinkDigest); err != nil {
		return store.transactionError(ctx, err)
	}
	if err := tx.Commit(); err != nil {
		return store.transactionError(ctx, err)
	}
	return nil
}

func (store *Store) ChainRange(ctx context.Context, first, last audit.EventID) (audit.ChainRange, error) {
	if first <= 0 || last < first {
		return audit.ChainRange{}, newStoreError("INPUT_INVALID", "audit-chain-range", false, nil)
	}
	rows, err := store.conn.QueryContext(ctx, `SELECT l.event_id,l.instance_id,l.recovery_epoch,l.segment_sequence,l.previous_digest,l.payload_digest,l.context_bytes,l.context_digest,l.link_digest,l.pre_anchor FROM audit_chain_links l WHERE l.event_id BETWEEN ? AND ? ORDER BY l.event_id`, first, last)
	if err != nil {
		return audit.ChainRange{}, store.transactionError(ctx, err)
	}
	defer rows.Close()
	var links []audit.ChainLink
	for rows.Next() {
		var link audit.ChainLink
		var contextBytes []byte
		var preAnchor int
		if err := rows.Scan(&link.EventID, &link.InstanceID, &link.RecoveryEpoch, &link.SegmentSequence, &link.PreviousDigest, &link.PayloadDigest, &contextBytes, &link.ContextDigest, &link.LinkDigest, &preAnchor); err != nil {
			return audit.ChainRange{}, store.transactionError(ctx, err)
		}
		var contextValue struct {
			Domain           string `json:"domain"`
			RunID            string `json:"runId"`
			PlanID           string `json:"planId"`
			ProviderNativeID string `json:"providerNativeId"`
		}
		if err := json.Unmarshal(contextBytes, &contextValue); err != nil || contextValue.Domain != "vegastack-labs.dev/audit-chain-context/v1" {
			return audit.ChainRange{}, newStoreError("INTEGRITY_FAILURE", "audit-chain-context", false, err)
		}
		link.Context = audit.ContextIDs{RunID: contextValue.RunID, PlanID: contextValue.PlanID, ProviderNativeID: contextValue.ProviderNativeID}
		link.PreAnchor = preAnchor == 1
		links = append(links, link)
	}
	if err := rows.Err(); err != nil {
		return audit.ChainRange{}, store.transactionError(ctx, err)
	}
	if len(links) == 0 || links[0].EventID != first || links[len(links)-1].EventID != last {
		return audit.ChainRange{}, newStoreError("STATE_CONFLICT", "audit-chain-range", false, nil)
	}
	digest, err := audit.DigestChainRange(links)
	if err != nil {
		return audit.ChainRange{}, newStoreError("INTEGRITY_FAILURE", "audit-chain-range", false, err)
	}
	return audit.ChainRange{FirstEventID: first, LastEventID: last, Links: links, RangeDigest: digest}, nil
}
