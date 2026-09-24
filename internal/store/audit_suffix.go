package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/vegastack/vegastack-labs/internal/audit"
)

const MaxRecoveryAuditSuffixEvents = 4096

// CanonicalAuditSuffix is evidence only. It contains canonical public audit
// events and chain links, with no executable provider request or effect body.
type CanonicalAuditSuffix struct {
	Events []audit.Event
	Chain  audit.ChainRange
	Digest audit.Fingerprint
}

func (store *Store) ReadAuditSuffix(ctx context.Context, first, last audit.EventID) (CanonicalAuditSuffix, error) {
	if store == nil || first <= 0 || last < first || int64(last-first)+1 > MaxRecoveryAuditSuffixEvents {
		return CanonicalAuditSuffix{}, newStoreError("INPUT_INVALID", "audit-recovery-suffix", false, nil)
	}
	rows, err := store.conn.QueryContext(ctx, `SELECT canonical_payload,payload_sha256 FROM audit_events WHERE event_id BETWEEN ? AND ? ORDER BY event_id`, first, last)
	if err != nil {
		return CanonicalAuditSuffix{}, store.transactionError(ctx, err)
	}
	defer rows.Close()
	result := CanonicalAuditSuffix{}
	var payloadDigests []audit.Fingerprint
	for rows.Next() {
		var raw []byte
		var stored audit.Fingerprint
		var event audit.Event
		if err := rows.Scan(&raw, &stored); err != nil {
			return CanonicalAuditSuffix{}, store.transactionError(ctx, err)
		}
		if json.Unmarshal(raw, &event) != nil {
			return CanonicalAuditSuffix{}, newStoreError("INTEGRITY_FAILURE", "audit-recovery-suffix", false, nil)
		}
		canonical, digest, err := audit.CanonicalEvent(event)
		if err != nil || !bytes.Equal(raw, canonical) || digest != stored {
			return CanonicalAuditSuffix{}, newStoreError("INTEGRITY_FAILURE", "audit-recovery-suffix", false, err)
		}
		payloadDigests = append(payloadDigests, digest)
		result.Events = append(result.Events, event)
	}
	if err := rows.Err(); err != nil {
		return CanonicalAuditSuffix{}, store.transactionError(ctx, err)
	}
	if len(result.Events) != int(last-first)+1 || result.Events[0].EventID != first || result.Events[len(result.Events)-1].EventID != last {
		return CanonicalAuditSuffix{}, newStoreError("STATE_CONFLICT", "audit-recovery-suffix", false, nil)
	}
	result.Chain, err = store.ChainRange(ctx, first, last)
	if err != nil {
		return CanonicalAuditSuffix{}, err
	}
	if _, err := audit.VerifyLocal(result.Chain.Links, result.Events, nil); err != nil {
		return CanonicalAuditSuffix{}, newStoreError("INTEGRITY_FAILURE", "audit-recovery-suffix", false, err)
	}
	digestInput, err := json.Marshal(struct {
		Domain         string              `json:"domain"`
		FirstEventID   audit.EventID       `json:"firstEventId"`
		LastEventID    audit.EventID       `json:"lastEventId"`
		PayloadDigests []audit.Fingerprint `json:"payloadDigests"`
		ChainDigest    audit.Fingerprint   `json:"chainDigest"`
	}{"vegastack-labs.dev/audit-recovery-suffix/v1", first, last, payloadDigests, result.Chain.RangeDigest})
	if err != nil {
		return CanonicalAuditSuffix{}, newStoreError("INTEGRITY_FAILURE", "audit-recovery-suffix", false, err)
	}
	sum := sha256.Sum256(digestInput)
	result.Digest = audit.Fingerprint("sha256:" + hex.EncodeToString(sum[:]))
	return result, nil
}
