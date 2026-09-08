package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"regexp"
	"sort"
	"time"

	"github.com/vegastack/vegastack-labs/internal/inventory"
)

var inventoryDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type InventoryDraftRepository struct {
	store            *Store
	beforeChildWrite func() error
}

func NewInventoryDraftRepository(store *Store) *InventoryDraftRepository {
	return &InventoryDraftRepository{store: store}
}

func (repository *InventoryDraftRepository) Put(ctx context.Context, request inventory.PutDraftRequest) (inventory.PutDraftResult, error) {
	if repository == nil || repository.store == nil || request.DraftID == "" || !inventoryDigestPattern.MatchString(request.IdempotencyKeyDigest) || !inventoryDigestPattern.MatchString(request.CandidateDigest) || request.CandidateDigest != request.Draft.ContentDigest || !inventoryDigestPattern.MatchString(request.Draft.Candidate.Source.Digest) || (request.Draft.ValidationStatus != inventory.DraftValid && request.Draft.ValidationStatus != inventory.DraftBlocked) {
		return inventory.PutDraftResult{}, newStoreError("INPUT_INVALID", "inventory-draft", false, nil)
	}
	if request.Draft.ValidationStatus == inventory.DraftValid {
		if err := validateInventoryProvenance(request.Draft.Candidate); err != nil {
			return inventory.PutDraftResult{}, err
		}
	}
	var expected *RevisionToken
	if request.ExpectedStateRevision != nil {
		var token RevisionToken
		if err := repository.store.Read(ctx, func(tx ReadTx) error {
			return tx.queryRow(ctx, `SELECT state_revision,recovery_epoch FROM system_meta WHERE id=1`).Scan(&token.StateRevision, &token.RecoveryEpoch)
		}); err != nil {
			return inventory.PutDraftResult{}, err
		}
		if token.StateRevision != *request.ExpectedStateRevision {
			return inventory.PutDraftResult{}, newStoreError("STATE_CONFLICT", "inventory-state-revision", false, nil)
		}
		expected = &token
	}
	var result inventory.PutDraftResult
	commit, err := repository.store.WriteIntent(ctx, expected, func(tx IntentTx) error {
		var candidateDigest, draftID string
		var revision int64
		err := tx.queryRow(ctx, `SELECT candidate_digest,draft_id,draft_revision FROM inventory_import_keys WHERE key_digest=?`, request.IdempotencyKeyDigest).Scan(&candidateDigest, &draftID, &revision)
		if err == nil {
			if candidateDigest != request.CandidateDigest {
				return newStoreError("STATE_CONFLICT", "inventory-import-key", false, nil)
			}
			result.Ref = inventory.DraftRef{ID: inventory.DraftID(draftID), Revision: revision}
			result.Created = false
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return classifySQLiteError(ctx, err)
		}
		source := request.Draft.Candidate.Source
		if source.Kind != "" && source.AdapterKind != "" && source.AdapterVersion != "" && source.SourceRevision != "" {
			var existingDigest string
			err = tx.queryRow(ctx, `SELECT source_digest FROM inventory_source_bindings WHERE source_kind=? AND adapter_kind=? AND adapter_version=? AND source_revision=?`, source.Kind, source.AdapterKind, source.AdapterVersion, source.SourceRevision).Scan(&existingDigest)
			if err == nil && existingDigest != source.Digest {
				return newStoreError("STATE_CONFLICT", "inventory-source-revision", false, nil)
			}
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				return classifySQLiteError(ctx, err)
			}
		}
		if err := tx.queryRow(ctx, `SELECT COALESCE(MAX(draft_revision),0)+1 FROM inventory_drafts WHERE draft_id=?`, request.DraftID).Scan(&revision); err != nil {
			return classifySQLiteError(ctx, err)
		}
		createdAt := repository.store.config.Clock().UTC().Format(time.RFC3339Nano)
		counts := request.Draft.Counts
		if _, err := tx.execChange(ctx, `INSERT INTO inventory_drafts(draft_id,draft_revision,validation_status,source_kind,adapter_kind,adapter_version,source_revision,source_digest,captured_at,content_digest,asset_count,node_count,alias_count,address_count,observation_count,hardware_fact_count,provenance_count,finding_count,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, request.DraftID, revision, request.Draft.ValidationStatus, source.Kind, source.AdapterKind, source.AdapterVersion, source.SourceRevision, source.Digest, source.CapturedAt.UTC().Format(time.RFC3339Nano), request.Draft.ContentDigest, counts.Assets, counts.Nodes, counts.Aliases, counts.Addresses, counts.Observations, counts.HardwareFacts, counts.Provenance, counts.Findings, createdAt); err != nil {
			return err
		}
		if repository.beforeChildWrite != nil {
			if err := repository.beforeChildWrite(); err != nil {
				return newStoreError("INTEGRITY_FAILURE", "inventory-draft-child", false, err)
			}
		}
		if err := repository.insertChildren(ctx, tx, request.DraftID, revision, request.Draft); err != nil {
			return err
		}
		if source.Kind != "" && source.AdapterKind != "" && source.AdapterVersion != "" && source.SourceRevision != "" {
			if _, err := tx.execChange(ctx, `INSERT OR IGNORE INTO inventory_source_bindings(source_kind,adapter_kind,adapter_version,source_revision,source_digest,draft_id,draft_revision) VALUES(?,?,?,?,?,?,?)`, source.Kind, source.AdapterKind, source.AdapterVersion, source.SourceRevision, source.Digest, request.DraftID, revision); err != nil {
				return err
			}
		}
		if _, err := tx.execChange(ctx, `INSERT INTO inventory_import_keys(key_digest,candidate_digest,draft_id,draft_revision) VALUES(?,?,?,?)`, request.IdempotencyKeyDigest, request.CandidateDigest, request.DraftID, revision); err != nil {
			return err
		}
		result.Ref = inventory.DraftRef{ID: request.DraftID, Revision: revision}
		result.Created = true
		return nil
	})
	if err != nil {
		return inventory.PutDraftResult{}, err
	}
	result.CommitStateRevision = commit.StateRevision
	result.RecoveryEpoch = commit.RecoveryEpoch
	return result, nil
}

func validateInventoryProvenance(candidate inventory.DraftCandidate) error {
	records := make(map[string]bool)
	for _, value := range candidate.Assets {
		records["asset\x00"+string(value.ID)] = true
	}
	for _, value := range candidate.Nodes {
		records["node\x00"+string(value.ID)] = true
	}
	for _, value := range candidate.Aliases {
		records["alias\x00"+string(value.ID)] = true
	}
	for _, value := range candidate.Addresses {
		records["address\x00"+string(value.ID)] = true
	}
	for _, value := range candidate.Observations {
		records["observation\x00"+string(value.ID)] = true
	}
	for _, value := range candidate.Provenance {
		if !records[value.RecordKind+"\x00"+string(value.RecordID)] {
			return newStoreError("STATE_CONFLICT", "inventory-provenance", false, nil)
		}
	}
	return nil
}

func (repository *InventoryDraftRepository) insertChildren(ctx context.Context, tx IntentTx, id inventory.DraftID, revision int64, draft inventory.NormalizedDraft) error {
	for assetOrdinal, asset := range draft.Candidate.Assets {
		if _, err := tx.execChange(ctx, `INSERT INTO inventory_draft_assets(draft_id,draft_revision,ordinal,local_id,kind,lifecycle) VALUES(?,?,?,?,?,?)`, id, revision, assetOrdinal, asset.ID, asset.Kind, asset.Lifecycle); err != nil {
			return err
		}
		for ordinal, identity := range asset.Identities {
			if _, err := tx.execChange(ctx, `INSERT INTO inventory_draft_identities(draft_id,draft_revision,asset_ordinal,ordinal,kind,value,quarantined) VALUES(?,?,?,?,?,?,?)`, id, revision, assetOrdinal, ordinal, identity.Kind, identity.Value, identity.Quarantined); err != nil {
				return err
			}
		}
		for factOrdinal, fact := range asset.HardwareFacts {
			if _, err := tx.execChange(ctx, `INSERT INTO inventory_draft_hardware_facts(draft_id,draft_revision,asset_ordinal,ordinal,local_id,kind,integer_value,text_value,unit) VALUES(?,?,?,?,?,?,?,?,?)`, id, revision, assetOrdinal, factOrdinal, fact.ID, fact.Kind, fact.IntegerValue, fact.TextValue, fact.Unit); err != nil {
				return err
			}
		}
	}
	for ordinal, value := range draft.Candidate.Nodes {
		if _, err := tx.execChange(ctx, `INSERT INTO inventory_draft_nodes(draft_id,draft_revision,ordinal,local_id,asset_id,parent_id) VALUES(?,?,?,?,?,?)`, id, revision, ordinal, value.ID, value.AssetID, value.ParentID); err != nil {
			return err
		}
	}
	for ordinal, value := range draft.Candidate.Aliases {
		if _, err := tx.execChange(ctx, `INSERT INTO inventory_draft_aliases(draft_id,draft_revision,ordinal,local_id,target_id,value) VALUES(?,?,?,?,?,?)`, id, revision, ordinal, value.ID, value.TargetID, value.Value); err != nil {
			return err
		}
	}
	for ordinal, value := range draft.Candidate.Addresses {
		if _, err := tx.execChange(ctx, `INSERT INTO inventory_draft_addresses(draft_id,draft_revision,ordinal,local_id,node_id,value) VALUES(?,?,?,?,?,?)`, id, revision, ordinal, value.ID, value.NodeID, value.Value); err != nil {
			return err
		}
	}
	for ordinal, value := range draft.Candidate.Observations {
		if _, err := tx.execChange(ctx, `INSERT INTO inventory_draft_observations(draft_id,draft_revision,ordinal,local_id,subject_id,kind,value,observed_at) VALUES(?,?,?,?,?,?,?,?)`, id, revision, ordinal, value.ID, value.SubjectID, value.Kind, value.Value, value.ObservedAt.UTC().Format(time.RFC3339Nano)); err != nil {
			return err
		}
	}
	for ordinal, value := range draft.Candidate.Provenance {
		if _, err := tx.execChange(ctx, `INSERT INTO inventory_draft_provenance(draft_id,draft_revision,ordinal,record_kind,record_id,field_path,locator,captured_at,adapter_version,value_status) VALUES(?,?,?,?,?,?,?,?,?,?)`, id, revision, ordinal, value.RecordKind, value.RecordID, value.FieldPath, value.Locator, value.CapturedAt.UTC().Format(time.RFC3339Nano), value.AdapterVersion, value.ValueStatus); err != nil {
			return err
		}
	}
	for ordinal, value := range draft.Findings {
		related, _ := json.Marshal(value.RelatedIDs)
		if _, err := tx.execChange(ctx, `INSERT INTO inventory_draft_findings(draft_id,draft_revision,ordinal,code,severity,blocking,record_kind,record_id,field_path,location,related_ids_json) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, id, revision, ordinal, value.Code, value.Severity, value.Blocking, value.RecordKind, value.RecordID, value.FieldPath, value.Location, string(related)); err != nil {
			return err
		}
	}
	return nil
}

func (repository *InventoryDraftRepository) Get(ctx context.Context, ref inventory.DraftRef) (inventory.PersistedDraft, error) {
	if repository == nil || repository.store == nil || ref.ID == "" || ref.Revision < 1 {
		return inventory.PersistedDraft{}, newStoreError("INPUT_INVALID", "inventory-draft-ref", false, nil)
	}
	var result inventory.PersistedDraft
	err := repository.store.Read(ctx, func(tx ReadTx) error { return repository.readDraft(ctx, tx, ref, &result) })
	return result, err
}

func (repository *InventoryDraftRepository) readDraft(ctx context.Context, tx ReadTx, ref inventory.DraftRef, result *inventory.PersistedDraft) error {
	var status string
	var capturedAt, createdAt string
	err := tx.queryRow(ctx, `SELECT validation_status,source_kind,adapter_kind,adapter_version,source_revision,source_digest,captured_at,content_digest,asset_count,node_count,alias_count,address_count,observation_count,hardware_fact_count,provenance_count,finding_count,created_at FROM inventory_drafts WHERE draft_id=? AND draft_revision=?`, ref.ID, ref.Revision).Scan(&status, &result.Source.Kind, &result.Source.AdapterKind, &result.Source.AdapterVersion, &result.Source.SourceRevision, &result.Source.Digest, &capturedAt, &result.ContentDigest, &result.Counts.Assets, &result.Counts.Nodes, &result.Counts.Aliases, &result.Counts.Addresses, &result.Counts.Observations, &result.Counts.HardwareFacts, &result.Counts.Provenance, &result.Counts.Findings, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return newStoreError("STATE_CONFLICT", "inventory-draft-ref", false, nil)
	}
	if err != nil {
		return classifySQLiteError(ctx, err)
	}
	result.Ref = ref
	result.ValidationStatus = inventory.DraftValidationStatus(status)
	result.Source.CapturedAt, _ = time.Parse(time.RFC3339Nano, capturedAt)
	result.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	assets, err := tx.query(ctx, `SELECT local_id,kind,lifecycle FROM inventory_draft_assets WHERE draft_id=? AND draft_revision=? ORDER BY ordinal`, ref.ID, ref.Revision)
	if err != nil {
		return err
	}
	for assets.Next() {
		var value inventory.DraftAsset
		if err := assets.Scan(&value.ID, &value.Kind, &value.Lifecycle); err != nil {
			_ = assets.Close()
			return err
		}
		result.Assets = append(result.Assets, value)
	}
	if err := assets.Close(); err != nil {
		return err
	}
	identities, err := tx.query(ctx, `SELECT asset_ordinal,kind,value,quarantined FROM inventory_draft_identities WHERE draft_id=? AND draft_revision=? ORDER BY asset_ordinal,ordinal`, ref.ID, ref.Revision)
	if err != nil {
		return err
	}
	for identities.Next() {
		var assetOrdinal int
		var value inventory.DraftIdentity
		if err := identities.Scan(&assetOrdinal, &value.Kind, &value.Value, &value.Quarantined); err != nil {
			_ = identities.Close()
			return err
		}
		result.Assets[assetOrdinal].Identities = append(result.Assets[assetOrdinal].Identities, value)
	}
	if err := identities.Close(); err != nil {
		return err
	}
	facts, err := tx.query(ctx, `SELECT asset_ordinal,local_id,kind,integer_value,text_value,unit FROM inventory_draft_hardware_facts WHERE draft_id=? AND draft_revision=? ORDER BY asset_ordinal,ordinal`, ref.ID, ref.Revision)
	if err != nil {
		return err
	}
	for facts.Next() {
		var assetOrdinal int
		var value inventory.DraftHardwareFact
		if err := facts.Scan(&assetOrdinal, &value.ID, &value.Kind, &value.IntegerValue, &value.TextValue, &value.Unit); err != nil {
			_ = facts.Close()
			return err
		}
		result.Assets[assetOrdinal].HardwareFacts = append(result.Assets[assetOrdinal].HardwareFacts, value)
	}
	if err := facts.Close(); err != nil {
		return err
	}
	if err := readSimpleRows(ctx, tx, `SELECT local_id,asset_id,parent_id FROM inventory_draft_nodes WHERE draft_id=? AND draft_revision=? ORDER BY ordinal`, ref, func(rows *sql.Rows) error {
		var value inventory.DraftNode
		if err := rows.Scan(&value.ID, &value.AssetID, &value.ParentID); err != nil {
			return err
		}
		result.Nodes = append(result.Nodes, value)
		return nil
	}); err != nil {
		return err
	}
	if err := readSimpleRows(ctx, tx, `SELECT local_id,target_id,value FROM inventory_draft_aliases WHERE draft_id=? AND draft_revision=? ORDER BY ordinal`, ref, func(rows *sql.Rows) error {
		var value inventory.DraftAlias
		if err := rows.Scan(&value.ID, &value.TargetID, &value.Value); err != nil {
			return err
		}
		result.Aliases = append(result.Aliases, value)
		return nil
	}); err != nil {
		return err
	}
	if err := readSimpleRows(ctx, tx, `SELECT local_id,node_id,value FROM inventory_draft_addresses WHERE draft_id=? AND draft_revision=? ORDER BY ordinal`, ref, func(rows *sql.Rows) error {
		var value inventory.DraftAddress
		if err := rows.Scan(&value.ID, &value.NodeID, &value.Value); err != nil {
			return err
		}
		result.Addresses = append(result.Addresses, value)
		return nil
	}); err != nil {
		return err
	}
	if err := readSimpleRows(ctx, tx, `SELECT local_id,subject_id,kind,value,observed_at FROM inventory_draft_observations WHERE draft_id=? AND draft_revision=? ORDER BY ordinal`, ref, func(rows *sql.Rows) error {
		var value inventory.DraftObservation
		var timestamp string
		if err := rows.Scan(&value.ID, &value.SubjectID, &value.Kind, &value.Value, &timestamp); err != nil {
			return err
		}
		value.ObservedAt, _ = time.Parse(time.RFC3339Nano, timestamp)
		result.Observations = append(result.Observations, value)
		return nil
	}); err != nil {
		return err
	}
	if err := readSimpleRows(ctx, tx, `SELECT record_kind,record_id,field_path,locator,captured_at,adapter_version,value_status FROM inventory_draft_provenance WHERE draft_id=? AND draft_revision=? ORDER BY ordinal`, ref, func(rows *sql.Rows) error {
		var value inventory.FieldProvenance
		var timestamp string
		if err := rows.Scan(&value.RecordKind, &value.RecordID, &value.FieldPath, &value.Locator, &timestamp, &value.AdapterVersion, &value.ValueStatus); err != nil {
			return err
		}
		value.CapturedAt, _ = time.Parse(time.RFC3339Nano, timestamp)
		result.Provenance = append(result.Provenance, value)
		return nil
	}); err != nil {
		return err
	}
	if err := readSimpleRows(ctx, tx, `SELECT code,severity,blocking,record_kind,record_id,field_path,location,related_ids_json FROM inventory_draft_findings WHERE draft_id=? AND draft_revision=? ORDER BY ordinal`, ref, func(rows *sql.Rows) error {
		var value inventory.Finding
		var related string
		if err := rows.Scan(&value.Code, &value.Severity, &value.Blocking, &value.RecordKind, &value.RecordID, &value.FieldPath, &value.Location, &related); err != nil {
			return err
		}
		if err := json.Unmarshal([]byte(related), &value.RelatedIDs); err != nil {
			return err
		}
		result.Findings = append(result.Findings, value)
		return nil
	}); err != nil {
		return err
	}
	return nil
}

func readSimpleRows(ctx context.Context, tx ReadTx, query string, ref inventory.DraftRef, scan func(*sql.Rows) error) error {
	rows, err := tx.query(ctx, query, ref.ID, ref.Revision)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		if err := scan(rows); err != nil {
			return err
		}
	}
	return rows.Err()
}

func (repository *InventoryDraftRepository) ListDrafts(ctx context.Context, query inventory.DraftListQuery) ([]inventory.DraftSummary, error) {
	if query.Limit < 1 || query.Limit > inventory.MaxQueryLimit {
		return nil, newStoreError("INPUT_INVALID", "inventory-draft-list", false, nil)
	}
	var result []inventory.DraftSummary
	cursorTime := listCursorTime(query.AfterCreatedAt)
	err := repository.store.Read(ctx, func(tx ReadTx) error {
		rows, err := tx.query(ctx, `SELECT draft_id,draft_revision,validation_status,content_digest,created_at,asset_count,node_count,alias_count,address_count,observation_count,hardware_fact_count,provenance_count,finding_count FROM inventory_drafts WHERE created_at>? OR (created_at=? AND (draft_id>? OR (draft_id=? AND draft_revision>?))) ORDER BY created_at,draft_id,draft_revision LIMIT ?`, cursorTime, cursorTime, query.AfterDraftID, query.AfterDraftID, query.AfterRevision, query.Limit)
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
			result = append(result, item)
		}
		return rows.Err()
	})
	return result, err
}

func listCursorTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}

func (repository *InventoryDraftRepository) ListRecords(ctx context.Context, ref inventory.DraftRef, query inventory.RecordListQuery) ([]inventory.DraftRecord, error) {
	if query.Limit < 1 || query.Limit > inventory.MaxQueryLimit {
		return nil, newStoreError("INPUT_INVALID", "inventory-record-list", false, nil)
	}
	draft, err := repository.Get(ctx, ref)
	if err != nil {
		return nil, err
	}
	var records []inventory.DraftRecord
	for _, value := range draft.Assets {
		records = append(records, inventory.DraftRecord{Kind: "asset", LocalID: value.ID})
		for _, fact := range value.HardwareFacts {
			records = append(records, inventory.DraftRecord{Kind: "hardware-fact", LocalID: inventory.LocalID(string(value.ID) + "/" + string(fact.ID))})
		}
	}
	for _, value := range draft.Nodes {
		records = append(records, inventory.DraftRecord{Kind: "node", LocalID: value.ID})
	}
	for _, value := range draft.Aliases {
		records = append(records, inventory.DraftRecord{Kind: "alias", LocalID: value.ID})
	}
	for _, value := range draft.Addresses {
		records = append(records, inventory.DraftRecord{Kind: "address", LocalID: value.ID})
	}
	for _, value := range draft.Observations {
		records = append(records, inventory.DraftRecord{Kind: "observation", LocalID: value.ID})
	}
	sort.Slice(records, func(i, j int) bool {
		return records[i].Kind+"\x00"+string(records[i].LocalID) < records[j].Kind+"\x00"+string(records[j].LocalID)
	})
	filtered := records[:0]
	cursor := query.AfterKind + "\x00" + string(query.AfterLocalID)
	for _, value := range records {
		if value.Kind+"\x00"+string(value.LocalID) > cursor {
			filtered = append(filtered, value)
			if len(filtered) == query.Limit {
				break
			}
		}
	}
	return filtered, nil
}

func (repository *InventoryDraftRepository) SnapshotDraft(ctx context.Context, ref inventory.DraftRef) (inventory.CanonicalDraftSnapshot, error) {
	draft, err := repository.Get(ctx, ref)
	if err != nil {
		return inventory.CanonicalDraftSnapshot{}, err
	}
	return inventory.CanonicalDraftSnapshot{Kind: "draft", Ref: draft.Ref, ValidationStatus: draft.ValidationStatus, Source: draft.Source, Assets: draft.Assets, Nodes: draft.Nodes, Aliases: draft.Aliases, Addresses: draft.Addresses, Observations: draft.Observations, Provenance: draft.Provenance, Findings: draft.Findings, ContentDigest: draft.ContentDigest}, nil
}

var _ inventory.DraftRepository = (*InventoryDraftRepository)(nil)
var _ inventory.ExportProjection = (*InventoryDraftRepository)(nil)
