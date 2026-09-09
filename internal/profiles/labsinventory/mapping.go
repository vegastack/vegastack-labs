package labsinventory

import (
	"context"
	"fmt"
	"time"

	"github.com/vegastack/vegastack-labs/internal/inventory"
)

const identityHardwareSerial = "hardware-serial"

func mapRecords(ctx context.Context, config Config, records [][]string) (inventory.DecodedCandidate, error) {
	decoded := inventory.DecodedCandidate{Candidate: inventory.DraftCandidate{Source: inventory.SourceDescriptor{
		Kind:           "csv",
		AdapterKind:    Format,
		AdapterVersion: AdapterVersion,
		SourceRevision: config.SourceRevision,
		CapturedAt:     config.CapturedAt,
	}}}
	activeOrdinal := 0
	for index, row := range records {
		if ctx.Err() != nil {
			return inventory.DecodedCandidate{}, decodeError(ErrorInterrupted, index+2, 0, "")
		}
		record := index + 2
		assetID := localID(record, "asset")
		lifecycle, active, lifecycleStatus, lifecycleFinding := mapLifecycle(record, row[0], assetID)
		asset := inventory.DraftAsset{ID: assetID, Kind: inventory.AssetPhysical, Lifecycle: lifecycle}
		if row[1] == "" {
			decoded.Findings = append(decoded.Findings, adapterFinding("MISSING_REQUIRED_FIELD", assetID, sourceFieldPath(record, "identities.hardware-serial"), rowLocator(record, "hardware_serial")))
		} else {
			asset.Identities = append(asset.Identities, inventory.DraftIdentity{
				Kind:        identityHardwareSerial,
				Value:       row[1],
				Quarantined: lifecycle == inventory.LifecycleQuarantined,
			})
		}
		decoded.Candidate.Assets = append(decoded.Candidate.Assets, asset)
		if lifecycleFinding.Code != "" {
			decoded.Findings = append(decoded.Findings, lifecycleFinding)
		}

		decoded.Candidate.Provenance = append(decoded.Candidate.Provenance,
			sourceProvenance(record, assetID, "lifecycle", lifecycleStatus, config.CapturedAt),
			sourceProvenance(record, assetID, "hardware_serial", sourceStatus(row[1], lifecycle), config.CapturedAt),
			sourceProvenance(record, assetID, "reported_hostname", sourceStatus(row[2], lifecycle), config.CapturedAt),
		)
		if !active {
			continue
		}

		activeOrdinal++
		nodeID := localID(record, "node")
		decoded.Candidate.Nodes = append(decoded.Candidate.Nodes, inventory.DraftNode{ID: nodeID, AssetID: assetID})
		proposed := fmt.Sprintf("vsk-node-%02d", activeOrdinal)
		proposedID := localID(record, "proposed-alias")
		decoded.Candidate.Aliases = append(decoded.Candidate.Aliases, inventory.DraftAlias{ID: proposedID, TargetID: nodeID, Value: proposed})
		decoded.Candidate.Provenance = append(decoded.Candidate.Provenance, aliasProvenance(record, proposedID, "proposed_alias", "derived", config.CapturedAt))

		if row[2] == "" {
			continue
		}
		if row[2] == proposed {
			decoded.Candidate.Provenance = append(decoded.Candidate.Provenance, aliasProvenance(record, proposedID, "reported_hostname", "reported", config.CapturedAt))
			continue
		}
		reportedID := localID(record, "reported-alias")
		decoded.Candidate.Aliases = append(decoded.Candidate.Aliases, inventory.DraftAlias{ID: reportedID, TargetID: nodeID, Value: row[2]})
		decoded.Candidate.Provenance = append(decoded.Candidate.Provenance, aliasProvenance(record, reportedID, "reported_hostname", "reported", config.CapturedAt))
	}
	return decoded, nil
}

func mapLifecycle(record int, value string, assetID inventory.LocalID) (inventory.AssetLifecycle, bool, string, inventory.Finding) {
	switch value {
	case "active":
		return inventory.LifecycleAvailable, true, "reported", inventory.Finding{}
	case "quarantined":
		return inventory.LifecycleQuarantined, false, "quarantined", inventory.Finding{}
	case "retired":
		return inventory.LifecycleRetired, false, "reported", inventory.Finding{}
	case "":
		return inventory.LifecycleCandidate, false, "missing", adapterFinding("MISSING_REQUIRED_FIELD", assetID, sourceFieldPath(record, "lifecycle"), rowLocator(record, "lifecycle"))
	default:
		return inventory.LifecycleCandidate, false, "invalid", adapterFinding("UNSUPPORTED_VALUE", assetID, sourceFieldPath(record, "lifecycle"), rowLocator(record, "lifecycle"))
	}
}

func sourceStatus(value string, lifecycle inventory.AssetLifecycle) string {
	if value == "" {
		return "missing"
	}
	if lifecycle == inventory.LifecycleQuarantined {
		return "quarantined"
	}
	return "reported"
}

func sourceProvenance(record int, assetID inventory.LocalID, field, status string, capturedAt time.Time) inventory.FieldProvenance {
	return inventory.FieldProvenance{
		RecordKind:     "asset",
		RecordID:       assetID,
		FieldPath:      sourceFieldPath(record, field),
		Locator:        rowLocator(record, field),
		CapturedAt:     capturedAt,
		AdapterVersion: AdapterVersion,
		ValueStatus:    status,
	}
}

func aliasProvenance(record int, aliasID inventory.LocalID, field, status string, capturedAt time.Time) inventory.FieldProvenance {
	return inventory.FieldProvenance{
		RecordKind:     "alias",
		RecordID:       aliasID,
		FieldPath:      "value",
		Locator:        rowLocator(record, field),
		CapturedAt:     capturedAt,
		AdapterVersion: AdapterVersion,
		ValueStatus:    status,
	}
}

func adapterFinding(code string, assetID inventory.LocalID, fieldPath, location string) inventory.Finding {
	return inventory.Finding{
		Code:       code,
		Severity:   "error",
		Blocking:   true,
		RecordKind: "asset",
		RecordID:   assetID,
		FieldPath:  fieldPath,
		Location:   location,
	}
}
