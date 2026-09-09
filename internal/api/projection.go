package api

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/inventory"
	"github.com/vegastack/vegastack-labs/internal/readmodel"
)

func counts(value inventory.DraftCounts) generated.InventoryDraftCounts {
	return generated.InventoryDraftCounts{Assets: int64(value.Assets), Nodes: int64(value.Nodes), Aliases: int64(value.Aliases), Addresses: int64(value.Addresses), Observations: int64(value.Observations), HardwareFacts: int64(value.HardwareFacts), Provenance: int64(value.Provenance), Findings: int64(value.Findings)}
}
func projectDraft(value inventory.DraftSummary) generated.ApiInventoryDraftData {
	return generated.ApiInventoryDraftData{Authority: "draft", DraftID: string(value.Ref.ID), Revision: value.Ref.Revision, ValidationStatus: string(value.ValidationStatus), ContentDigest: value.ContentDigest, CreatedAt: value.CreatedAt.UTC().Format("2006-01-02T15:04:05.999999999Z07:00"), Counts: counts(value.Counts)}
}
func projectDraftPage(value readmodel.DraftPage, next *string) generated.ApiInventoryDraftListData {
	items := make([]generated.ApiInventoryDraftData, 0, len(value.Items))
	for _, item := range value.Items {
		items = append(items, projectDraft(item))
	}
	return generated.ApiInventoryDraftListData{Items: items, NextCursor: next, StateRevision: value.Snapshot.StateRevision, RecoveryEpoch: value.Snapshot.RecoveryEpoch}
}
func projectDatabaseStatus(value readmodel.DatabaseStatus) generated.DatabaseStatusData {
	var checked *string
	if value.LastIntegrityCheckAt != nil {
		x := value.LastIntegrityCheckAt.UTC().Format("2006-01-02T15:04:05.999999999Z07:00")
		checked = &x
	}
	return generated.DatabaseStatusData{Mode: value.Mode, SchemaVersion: int64(value.SchemaVersion), SQLiteVersion: value.SQLiteVersion, MutationEnabled: value.MutationEnabled, RecoveryPending: value.RecoveryPending, IntegrityStatus: value.IntegrityStatus, LastIntegrityCheckAt: checked, SafeModeReason: value.SafeModeReason}
}
func projectSummary(v readmodel.Summary) generated.ApiSummaryData {
	return generated.ApiSummaryData{DatabaseMode: v.DatabaseMode, ReadAvailable: v.ReadAvailable, MutationAvailable: v.MutationAvailable, DraftCount: v.DraftCount, ValidDraftCount: v.ValidDraftCount, BlockedDraftCount: v.BlockedDraftCount, LastEventID: v.LastEventID, RecoveryEpoch: v.RecoveryEpoch, StateRevision: v.StateRevision}
}
func projectRecord(kind string, v readmodel.Record) any {
	switch kind {
	case "asset":
		return generated.ApiInventoryAssetData{Authority: "draft", ValidationStatus: v.ValidationStatus, ID: string(v.LocalID), Kind: string(v.AssetKind), Lifecycle: string(v.Lifecycle)}
	case "node":
		return generated.ApiInventoryNodeData{Authority: "draft", ValidationStatus: v.ValidationStatus, ID: string(v.LocalID), AssetID: string(v.AssetID), ParentID: string(v.ParentID)}
	case "alias":
		return generated.ApiInventoryAliasData{Authority: "draft", ValidationStatus: v.ValidationStatus, ID: string(v.LocalID), TargetID: string(v.TargetID), Value: v.Value}
	default:
		var observed *string
		if v.ObservedAt != nil {
			x := v.ObservedAt.UTC().Format("2006-01-02T15:04:05.999999999Z07:00")
			observed = &x
		}
		return generated.ApiInventoryObservationData{Authority: "draft", ValidationStatus: v.ValidationStatus, ID: string(v.LocalID), SubjectID: string(v.SubjectID), Kind: v.ObservationKind, State: v.State, ObservedAt: observed, Source: v.Source}
	}
}
func projectRecordPage(kind string, v readmodel.RecordPage, next *string) any {
	switch kind {
	case "asset":
		items := make([]generated.ApiInventoryAssetData, 0, len(v.Items))
		for _, x := range v.Items {
			items = append(items, projectRecord(kind, x).(generated.ApiInventoryAssetData))
		}
		return generated.ApiInventoryAssetListData{Items: items, NextCursor: next, StateRevision: v.Snapshot.StateRevision, RecoveryEpoch: v.Snapshot.RecoveryEpoch}
	case "node":
		items := make([]generated.ApiInventoryNodeData, 0, len(v.Items))
		for _, x := range v.Items {
			items = append(items, projectRecord(kind, x).(generated.ApiInventoryNodeData))
		}
		return generated.ApiInventoryNodeListData{Items: items, NextCursor: next, StateRevision: v.Snapshot.StateRevision, RecoveryEpoch: v.Snapshot.RecoveryEpoch}
	case "alias":
		items := make([]generated.ApiInventoryAliasData, 0, len(v.Items))
		for _, x := range v.Items {
			items = append(items, projectRecord(kind, x).(generated.ApiInventoryAliasData))
		}
		return generated.ApiInventoryAliasListData{Items: items, NextCursor: next, StateRevision: v.Snapshot.StateRevision, RecoveryEpoch: v.Snapshot.RecoveryEpoch}
	default:
		items := make([]generated.ApiInventoryObservationData, 0, len(v.Items))
		for _, x := range v.Items {
			items = append(items, projectRecord(kind, x).(generated.ApiInventoryObservationData))
		}
		return generated.ApiInventoryObservationListData{Items: items, NextCursor: next, StateRevision: v.Snapshot.StateRevision, RecoveryEpoch: v.Snapshot.RecoveryEpoch}
	}
}
