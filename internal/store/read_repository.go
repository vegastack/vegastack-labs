package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/inventory"
	"github.com/vegastack/vegastack-labs/internal/readmodel"
)

type ReadRepository struct{ store *Store }

func NewReadRepository(store *Store) *ReadRepository { return &ReadRepository{store: store} }

func (repository *ReadRepository) DatabaseStatus(ctx context.Context, scope authorization.ReadScope) (readmodel.DatabaseStatus, error) {
	var result readmodel.DatabaseStatus
	err := repository.store.Read(ctx, func(tx ReadTx) error {
		if err := verifyReadScope(ctx, tx, scope, ""); err != nil {
			return err
		}
		health := repository.store.health
		result = readmodel.DatabaseStatus{Mode: string(health.Mode), SchemaVersion: health.SchemaVersion, SQLiteVersion: health.SQLiteVersion, Revision: readmodel.RevisionToken{StateRevision: health.Revision.StateRevision, RecoveryEpoch: health.Revision.RecoveryEpoch}, MutationEnabled: health.MutationEnabled, RecoveryPending: health.RecoveryPending, IntegrityStatus: string(health.IntegrityStatus), LastIntegrityCheckAt: health.LastIntegrityCheckAt, SafeModeReason: health.SafeModeReason}
		return nil
	})
	return result, err
}

func (repository *ReadRepository) Summary(ctx context.Context, scope authorization.ReadScope) (readmodel.Summary, error) {
	var result readmodel.Summary
	err := repository.store.Read(ctx, func(tx ReadTx) error {
		if err := verifyReadScope(ctx, tx, scope, ""); err != nil {
			return err
		}
		var mode string
		if err := tx.queryRow(ctx, `SELECT (SELECT COUNT(*) FROM inventory_drafts),(SELECT COUNT(*) FROM inventory_drafts WHERE validation_status='valid'),(SELECT COUNT(*) FROM inventory_drafts WHERE validation_status='blocked'),audit_sequence,state_revision,recovery_epoch FROM system_meta WHERE id=1`).Scan(&result.DraftCount, &result.ValidDraftCount, &result.BlockedDraftCount, &result.LastEventID, &result.StateRevision, &result.RecoveryEpoch); err != nil {
			return err
		}
		mode = string(repository.store.health.Mode)
		result.DatabaseMode = mode
		result.ReadAvailable = true
		result.MutationAvailable = false
		return nil
	})
	return result, err
}

func (repository *ReadRepository) ListDrafts(ctx context.Context, scope authorization.ReadScope, query inventory.DraftListQuery, snapshot RevisionToken) (readmodel.DraftPage, error) {
	if query.Limit < 1 || query.Limit > 200 {
		return readmodel.DraftPage{}, newStoreError(generated.ErrorCodeInputInvalid, "read", false, nil)
	}
	result := readmodel.DraftPage{Snapshot: readmodel.RevisionToken{StateRevision: snapshot.StateRevision, RecoveryEpoch: snapshot.RecoveryEpoch}}
	err := repository.store.Read(ctx, func(tx ReadTx) error {
		if err := verifySnapshot(ctx, tx, snapshot); err != nil {
			return err
		}
		if err := verifyReadScope(ctx, tx, scope, ""); err != nil {
			return err
		}
		direction, comparison := "ASC", ">"
		if query.Sort == "created-at-desc" {
			direction, comparison = "DESC", "<"
		} else if query.Sort != "" && query.Sort != "created-at-asc" {
			return newStoreError(generated.ErrorCodeInputInvalid, "read", false, nil)
		}
		cursorTime := listCursorTime(query.AfterCreatedAt)
		if direction == "DESC" && query.AfterCreatedAt.IsZero() {
			cursorTime = "9999-12-31T23:59:59.999999999Z"
			query.AfterDraftID = inventory.DraftID(strings.Repeat("z", 128))
			query.AfterRevision = int64(^uint64(0) >> 1)
		}
		statement := fmt.Sprintf(`SELECT d.draft_id,d.draft_revision,d.validation_status,d.content_digest,d.created_at,d.asset_count,d.node_count,d.alias_count,d.address_count,d.observation_count,d.hardware_fact_count,d.provenance_count,d.finding_count
FROM inventory_drafts d
JOIN read_grants g ON g.principal_id=? AND g.capability=? AND g.resource_kind=? AND g.resource_id=d.draft_id||':'||CAST(d.draft_revision AS TEXT) AND g.status='active' AND g.grant_revision=?
JOIN audit_events e ON e.target_kind='inventory-draft' AND e.target_id=d.draft_id AND e.after_fingerprint=d.content_digest AND e.state_revision<=?
WHERE d.created_at%s? OR (d.created_at=? AND (d.draft_id%s? OR (d.draft_id=? AND d.draft_revision%s?)))
ORDER BY d.created_at %s,d.draft_id %s,d.draft_revision %s LIMIT ?`, comparison, comparison, comparison, direction, direction, direction)
		rows, err := tx.query(ctx, statement, scope.PrincipalID, scope.Capability, scope.ResourceKind, scope.GrantRevision, snapshot.StateRevision, cursorTime, cursorTime, query.AfterDraftID, query.AfterDraftID, query.AfterRevision, query.Limit+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var item inventory.DraftSummary
			var status, created string
			if err := rows.Scan(&item.Ref.ID, &item.Ref.Revision, &status, &item.ContentDigest, &created, &item.Counts.Assets, &item.Counts.Nodes, &item.Counts.Aliases, &item.Counts.Addresses, &item.Counts.Observations, &item.Counts.HardwareFacts, &item.Counts.Provenance, &item.Counts.Findings); err != nil {
				return err
			}
			item.ValidationStatus = inventory.DraftValidationStatus(status)
			item.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
			result.Items = append(result.Items, item)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		if len(result.Items) > query.Limit {
			result.Items = result.Items[:query.Limit]
			result.HasMore = true
		}
		if result.HasMore {
			last := result.Items[len(result.Items)-1]
			result.Last = &inventory.DraftListQuery{AfterCreatedAt: last.CreatedAt, AfterDraftID: last.Ref.ID, AfterRevision: last.Ref.Revision, Limit: query.Limit, Sort: query.Sort}
		}
		return nil
	})
	return result, err
}

func (repository *ReadRepository) GetDraft(ctx context.Context, scope authorization.ReadScope, ref inventory.DraftRef) (readmodel.Draft, error) {
	var result readmodel.Draft
	resource := authorization.ResourceID(ref)
	if resource == "" {
		return result, newStoreError(generated.ErrorCodeInputInvalid, "read", false, nil)
	}
	err := repository.store.Read(ctx, func(tx ReadTx) error {
		if err := verifyReadScope(ctx, tx, scope, resource); err != nil {
			return err
		}
		var status, created, captured string
		err := tx.queryRow(ctx, `SELECT d.validation_status,d.content_digest,d.created_at,d.asset_count,d.node_count,d.alias_count,d.address_count,d.observation_count,d.hardware_fact_count,d.provenance_count,d.finding_count,d.source_kind,d.adapter_kind,d.adapter_version,d.source_revision,d.source_digest,d.captured_at FROM inventory_drafts d JOIN read_grants g ON g.principal_id=? AND g.capability=? AND g.resource_kind=? AND g.resource_id=d.draft_id||':'||CAST(d.draft_revision AS TEXT) AND g.status='active' AND g.grant_revision=? WHERE d.draft_id=? AND d.draft_revision=?`, scope.PrincipalID, scope.Capability, scope.ResourceKind, scope.GrantRevision, ref.ID, ref.Revision).Scan(&status, &result.Summary.ContentDigest, &created, &result.Summary.Counts.Assets, &result.Summary.Counts.Nodes, &result.Summary.Counts.Aliases, &result.Summary.Counts.Addresses, &result.Summary.Counts.Observations, &result.Summary.Counts.HardwareFacts, &result.Summary.Counts.Provenance, &result.Summary.Counts.Findings, &result.Source.Kind, &result.Source.AdapterKind, &result.Source.AdapterVersion, &result.Source.SourceRevision, &result.Source.Digest, &captured)
		if errors.Is(err, sql.ErrNoRows) {
			return newStoreError(generated.ErrorCodeResourceNotFound, "read", false, nil)
		}
		if err != nil {
			return err
		}
		result.Summary.Ref = ref
		result.Summary.ValidationStatus = inventory.DraftValidationStatus(status)
		result.Summary.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		result.Source.CapturedAt, _ = time.Parse(time.RFC3339Nano, captured)
		return nil
	})
	return result, err
}

func (repository *ReadRepository) ListRecords(ctx context.Context, scope authorization.ReadScope, ref inventory.DraftRef, query inventory.RecordListQuery, snapshot RevisionToken) (readmodel.RecordPage, error) {
	if query.Limit < 1 || query.Limit > 200 {
		return readmodel.RecordPage{}, newStoreError(generated.ErrorCodeInputInvalid, "read", false, nil)
	}
	result := readmodel.RecordPage{Snapshot: readmodel.RevisionToken{StateRevision: snapshot.StateRevision, RecoveryEpoch: snapshot.RecoveryEpoch}}
	err := repository.store.Read(ctx, func(tx ReadTx) error {
		if err := verifySnapshot(ctx, tx, snapshot); err != nil {
			return err
		}
		if err := verifyReadScope(ctx, tx, scope, authorization.ResourceID(ref)); err != nil {
			return err
		}
		records, err := readRecordRows(ctx, tx, scope, ref, query.AfterKind, query.AfterLocalID, "", query.Limit+1, query.Sort)
		if err != nil {
			return err
		}
		result.Items = records
		if len(result.Items) > query.Limit {
			result.Items = result.Items[:query.Limit]
			result.HasMore = true
		}
		if result.HasMore {
			last := result.Items[len(result.Items)-1]
			result.Last = &inventory.RecordListQuery{AfterKind: last.Kind, AfterLocalID: last.LocalID, Limit: query.Limit, Sort: query.Sort}
		}
		return nil
	})
	return result, err
}

func (repository *ReadRepository) GetRecord(ctx context.Context, scope authorization.ReadScope, ref inventory.DraftRef, kind string, id inventory.LocalID) (readmodel.Record, error) {
	var result readmodel.Record
	if id == "" {
		return result, newStoreError(generated.ErrorCodeInputInvalid, "read", false, nil)
	}
	err := repository.store.Read(ctx, func(tx ReadTx) error {
		if err := verifyReadScope(ctx, tx, scope, authorization.ResourceID(ref)); err != nil {
			return err
		}
		items, err := readRecordRows(ctx, tx, scope, ref, kind, "", id, 1, "")
		if err != nil {
			return err
		}
		for _, item := range items {
			if item.LocalID == id {
				result = item
				return nil
			}
		}
		return newStoreError(generated.ErrorCodeResourceNotFound, "read", false, nil)
	})
	return result, err
}

func readRecordRows(ctx context.Context, tx ReadTx, scope authorization.ReadScope, ref inventory.DraftRef, kind string, after, exact inventory.LocalID, limit int, sortName string) ([]readmodel.Record, error) {
	if kind != "asset" && kind != "node" && kind != "alias" && kind != "observation" {
		return nil, newStoreError(generated.ErrorCodeInputInvalid, "read", false, nil)
	}
	table, columns := "", ""
	switch kind {
	case "asset":
		table, columns = "inventory_draft_assets", "local_id,kind,lifecycle"
	case "node":
		table, columns = "inventory_draft_nodes", "local_id,asset_id,parent_id"
	case "alias":
		table, columns = "inventory_draft_aliases", "local_id,target_id,value"
	case "observation":
		table, columns = "inventory_draft_observations", "local_id,subject_id,kind,observed_at"
	}
	direction, comparison := "ASC", ">"
	if strings.HasSuffix(sortName, "-desc") {
		direction, comparison = "DESC", "<"
		if after == "" {
			after = inventory.LocalID(strings.Repeat("z", 128))
		}
	}
	statement := fmt.Sprintf(`SELECT r.%s FROM %s r JOIN read_grants g ON g.principal_id=? AND g.capability=? AND g.resource_kind=? AND g.resource_id=r.draft_id||':'||CAST(r.draft_revision AS TEXT) AND g.status='active' AND g.grant_revision=? WHERE r.draft_id=? AND r.draft_revision=? AND (?='' OR r.local_id=?) AND r.local_id%s? ORDER BY r.local_id %s LIMIT ?`, strings.ReplaceAll(columns, ",", ",r."), table, comparison, direction)
	rows, err := tx.query(ctx, statement, scope.PrincipalID, scope.Capability, scope.ResourceKind, scope.GrantRevision, ref.ID, ref.Revision, exact, exact, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []readmodel.Record
	for rows.Next() {
		item := readmodel.Record{Kind: kind}
		switch kind {
		case "asset":
			err = rows.Scan(&item.LocalID, &item.AssetKind, &item.Lifecycle)
		case "node":
			err = rows.Scan(&item.LocalID, &item.AssetID, &item.ParentID)
		case "alias":
			err = rows.Scan(&item.LocalID, &item.TargetID, &item.Value)
		case "observation":
			var observed string
			err = rows.Scan(&item.LocalID, &item.SubjectID, &item.ObservationKind, &observed)
			if err == nil {
				parsed, parseErr := time.Parse(time.RFC3339Nano, observed)
				if parseErr != nil {
					return nil, parseErr
				}
				item.ObservedAt = &parsed
				item.State = "observed"
				item.Source = "inventory-draft"
			}
		}
		if err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (repository *ReadRepository) ReadEvents(ctx context.Context, scope authorization.ReadScope, after audit.EventID, limit int) (readmodel.EventBatch, error) {
	if after < 0 || limit < 1 || limit > 200 {
		return readmodel.EventBatch{}, newStoreError(generated.ErrorCodeInputInvalid, "read", false, nil)
	}
	var result readmodel.EventBatch
	err := repository.store.Read(ctx, func(tx ReadTx) error {
		if err := verifyReadScope(ctx, tx, scope, ""); err != nil {
			return err
		}
		if err := tx.queryRow(ctx, `SELECT audit_sequence FROM system_meta WHERE id=1`).Scan(&result.HighWater); err != nil {
			return err
		}
		rows, err := tx.query(ctx, `SELECT e.canonical_payload FROM audit_events e WHERE EXISTS (SELECT 1 FROM read_grants g WHERE g.principal_id=? AND g.capability=? AND g.resource_kind=? AND g.status='active' AND g.grant_revision=?) AND e.event_id>? ORDER BY e.event_id LIMIT ?`, scope.PrincipalID, scope.Capability, scope.ResourceKind, scope.GrantRevision, after, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var payload []byte
			var event audit.Event
			if err := rows.Scan(&payload); err != nil {
				return err
			}
			if err := json.Unmarshal(payload, &event); err != nil {
				return newStoreError(generated.ErrorCodeIntegrityFailure, "read", false, err)
			}
			result.Items = append(result.Items, event)
		}
		return rows.Err()
	})
	return result, err
}

func (repository *ReadRepository) EventHighWater(ctx context.Context, scope authorization.ReadScope) (audit.EventID, error) {
	batch, err := repository.ReadEvents(ctx, scope, 0, 1)
	return batch.HighWater, err
}
func (repository *ReadRepository) EventExists(ctx context.Context, scope authorization.ReadScope, id audit.EventID) (bool, error) {
	if id <= 0 {
		return false, nil
	}
	batch, err := repository.ReadEvents(ctx, scope, id-1, 1)
	return err == nil && len(batch.Items) == 1 && batch.Items[0].EventID == id, err
}

func verifySnapshot(ctx context.Context, tx ReadTx, snapshot RevisionToken) error {
	var current RevisionToken
	if err := tx.queryRow(ctx, `SELECT state_revision,recovery_epoch FROM system_meta WHERE id=1`).Scan(&current.StateRevision, &current.RecoveryEpoch); err != nil {
		return err
	}
	if snapshot.RecoveryEpoch != current.RecoveryEpoch || snapshot.StateRevision < 0 || snapshot.StateRevision > current.StateRevision {
		return newStoreError(generated.ErrorCodeStateConflict, "read", false, nil)
	}
	return nil
}

func verifyReadScope(ctx context.Context, tx ReadTx, scope authorization.ReadScope, exactResource string) error {
	deny := func(cause error) error {
		return newStoreError(generated.ErrorCodeAuthorizationDenied, "read", false, cause)
	}
	if scope.PrincipalID == "" || scope.Capability == "" || scope.ResourceKind == "" || scope.GrantRevision <= 0 || scope.ScopeDigest == "" {
		return deny(nil)
	}
	var status string
	var revision int64
	if err := tx.queryRow(ctx, `SELECT status,grant_revision FROM read_principals WHERE principal_id=?`, scope.PrincipalID).Scan(&status, &revision); err != nil || status != "active" || revision != scope.GrantRevision {
		return deny(err)
	}
	rows, err := tx.query(ctx, `SELECT resource_id,grant_revision FROM read_grants WHERE principal_id=? AND capability=? AND resource_kind=? AND status='active' AND (?='' OR resource_id=?) ORDER BY resource_id`, scope.PrincipalID, scope.Capability, scope.ResourceKind, exactResource, exactResource)
	if err != nil {
		return deny(err)
	}
	defer rows.Close()
	var resources []string
	for rows.Next() {
		var resource string
		var grantRevision int64
		if err := rows.Scan(&resource, &grantRevision); err != nil {
			return deny(err)
		}
		if grantRevision != revision {
			return deny(nil)
		}
		resources = append(resources, resource)
	}
	if err := rows.Err(); err != nil {
		return deny(err)
	}
	if len(resources) == 0 || scopeDigest(scope.PrincipalID, scope.Capability, scope.ResourceKind, revision, resources) != scope.ScopeDigest {
		return deny(nil)
	}
	return nil
}
