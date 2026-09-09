//go:build linux

package store

import (
	"context"
	"database/sql"
	"errors"

	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/inventory"
	"github.com/vegastack/vegastack-labs/internal/inventoryops"
)

func (repository *InventoryDraftRepository) ResolveDiffSnapshot(ctx context.Context, request inventoryops.DiffSnapshotRequest) (inventoryops.ResolvedDiffSnapshot, error) {
	var result inventoryops.ResolvedDiffSnapshot
	if repository == nil || repository.store == nil || request.Scope.Capability != "inventory.draft.diff" || request.Scope.ResourceKind != "inventory-draft" {
		return result, newStoreError(generated.ErrorCodeAuthorizationDenied, "inventory-diff", false, nil)
	}
	err := repository.store.Read(ctx, func(tx ReadTx) error {
		if err := verifyReadScope(ctx, tx, request.Scope, ""); err != nil {
			return err
		}
		if err := tx.queryRow(ctx, `SELECT state_revision,recovery_epoch FROM system_meta WHERE id=1`).Scan(&result.StateRevision, &result.RecoveryEpoch); err != nil {
			return err
		}

		lineage := request.Lineage
		if request.Candidate != nil {
			if request.Candidate.ID == "" || request.Candidate.Revision < 1 {
				return newStoreError(generated.ErrorCodeInputInvalid, "inventory-diff-candidate", false, nil)
			}
			resource := authorization.ResourceID(*request.Candidate)
			var count int
			if err := tx.queryRow(ctx, `SELECT COUNT(*) FROM read_grants WHERE principal_id=? AND capability=? AND resource_kind=? AND resource_id=? AND grant_revision=? AND status='active'`, request.Scope.PrincipalID, request.Scope.Capability, request.Scope.ResourceKind, resource, request.Scope.GrantRevision).Scan(&count); err != nil {
				return err
			}
			if count != 1 {
				return newStoreError(generated.ErrorCodeAuthorizationDenied, "inventory-diff", false, nil)
			}
			var persisted inventory.PersistedDraft
			if err := repository.readDraft(ctx, tx, *request.Candidate, &persisted); err != nil {
				return newStoreError(generated.ErrorCodeAuthorizationDenied, "inventory-diff", false, nil)
			}
			value := canonicalSnapshot(persisted)
			result.Candidate = &value
			lineage = inventoryops.Lineage{SourceKind: persisted.Source.Kind, AdapterKind: persisted.Source.AdapterKind, AdapterVersion: persisted.Source.AdapterVersion}
		}
		if lineage.SourceKind == "" || lineage.AdapterKind == "" || lineage.AdapterVersion == "" {
			return newStoreError(generated.ErrorCodeInputInvalid, "inventory-diff-lineage", false, nil)
		}
		candidateID, candidateRevision := "", int64(0)
		if request.Candidate != nil {
			candidateID, candidateRevision = string(request.Candidate.ID), request.Candidate.Revision
		}
		var baseline inventory.DraftRef
		err := tx.queryRow(ctx, `SELECT d.draft_id,d.draft_revision
FROM inventory_drafts d
JOIN read_grants g ON g.principal_id=? AND g.capability=? AND g.resource_kind=? AND g.resource_id=d.draft_id||':'||CAST(d.draft_revision AS TEXT) AND g.status='active' AND g.grant_revision=?
JOIN audit_events e ON e.event_type='inventory.draft.persisted' AND e.target_kind='inventory-draft' AND e.target_id=d.draft_id AND e.after_fingerprint=d.content_digest
WHERE d.source_kind=? AND d.adapter_kind=? AND d.adapter_version=? AND e.state_revision<=? AND NOT (d.draft_id=? AND d.draft_revision=?)
ORDER BY e.state_revision DESC,d.draft_id DESC,d.draft_revision DESC LIMIT 1`,
			request.Scope.PrincipalID, request.Scope.Capability, request.Scope.ResourceKind, request.Scope.GrantRevision,
			lineage.SourceKind, lineage.AdapterKind, lineage.AdapterVersion, result.StateRevision, candidateID, candidateRevision).Scan(&baseline.ID, &baseline.Revision)
		if errors.Is(err, sql.ErrNoRows) {
			return newStoreError(generated.ErrorCodePrerequisiteBlocked, "inventory-diff-baseline", false, nil)
		}
		if err != nil {
			return err
		}
		var persisted inventory.PersistedDraft
		if err := repository.readDraft(ctx, tx, baseline, &persisted); err != nil {
			return err
		}
		result.Baseline = canonicalSnapshot(persisted)
		return nil
	})
	return result, err
}

func canonicalSnapshot(draft inventory.PersistedDraft) inventory.CanonicalDraftSnapshot {
	return inventory.CanonicalDraftSnapshot{Kind: "draft", Ref: draft.Ref, ValidationStatus: draft.ValidationStatus, Source: draft.Source,
		Assets: draft.Assets, Nodes: draft.Nodes, Aliases: draft.Aliases, Addresses: draft.Addresses, Observations: draft.Observations,
		Provenance: draft.Provenance, Findings: draft.Findings, ContentDigest: draft.ContentDigest}
}

var _ inventoryops.DiffRepository = (*InventoryDraftRepository)(nil)
