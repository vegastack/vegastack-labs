package inventory

import (
	"context"
	"net/netip"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

var allowedFindingCodes = map[string]bool{"DUPLICATE_RECORD_ID": true, "DUPLICATE_IDENTITY": true, "DUPLICATE_ALIAS": true, "DUPLICATE_ADDRESS": true, "MISSING_REFERENCE": true, "REFERENCE_CYCLE": true, "IDENTITY_CONFLICT": true, "IDENTITY_QUARANTINED": true, "IDENTITY_UNSUPPORTED": true, "UNSUPPORTED_VALUE": true, "INVALID_CAPACITY": true, "MISSING_REQUIRED_FIELD": true, "PROHIBITED_SECRET_VALUE": true}

func validateBoundsAndSecrets(candidate DraftCandidate, findings []Finding) error {
	primary := len(candidate.Assets) + len(candidate.Nodes) + len(candidate.Aliases) + len(candidate.Addresses) + len(candidate.Observations)
	facts := 0
	if primary > MaxPrimaryRecords || len(candidate.Provenance) > MaxProvenance {
		return newError(generated.ErrorCodeInputInvalid, targetDraft)
	}
	stringsToCheck := []string{candidate.Source.Kind, candidate.Source.AdapterKind, candidate.Source.AdapterVersion, candidate.Source.SourceRevision, candidate.Source.Digest}
	if candidate.Source.Kind == "" || candidate.Source.AdapterKind == "" || candidate.Source.AdapterVersion == "" || !canonicalTime(candidate.Source.CapturedAt) {
		return newError(generated.ErrorCodeInputInvalid, targetDraft)
	}
	for _, asset := range candidate.Assets {
		if len(asset.Identities) > MaxIdentities || len(asset.HardwareFacts) > MaxFactsPerAsset {
			return newError(generated.ErrorCodeInputInvalid, targetDraft)
		}
		facts += len(asset.HardwareFacts)
		stringsToCheck = append(stringsToCheck, string(asset.ID), string(asset.Kind), string(asset.Lifecycle))
		for _, identity := range asset.Identities {
			stringsToCheck = append(stringsToCheck, identity.Kind, identity.Value)
		}
		for _, fact := range asset.HardwareFacts {
			stringsToCheck = append(stringsToCheck, string(fact.ID), fact.Kind, fact.Unit)
			if fact.TextValue != nil {
				stringsToCheck = append(stringsToCheck, *fact.TextValue)
			}
		}
	}
	if facts > MaxHardwareFacts {
		return newError(generated.ErrorCodeInputInvalid, targetDraft)
	}
	for _, node := range candidate.Nodes {
		stringsToCheck = append(stringsToCheck, string(node.ID), string(node.AssetID), string(node.ParentID))
	}
	for _, alias := range candidate.Aliases {
		stringsToCheck = append(stringsToCheck, string(alias.ID), string(alias.TargetID), alias.Value)
	}
	for _, address := range candidate.Addresses {
		stringsToCheck = append(stringsToCheck, string(address.ID), string(address.NodeID), address.Value)
	}
	for _, observation := range candidate.Observations {
		stringsToCheck = append(stringsToCheck, string(observation.ID), string(observation.SubjectID), observation.Kind, observation.Value)
	}
	for _, provenance := range candidate.Provenance {
		stringsToCheck = append(stringsToCheck, provenance.RecordKind, string(provenance.RecordID), provenance.FieldPath, provenance.Locator, provenance.AdapterVersion, provenance.ValueStatus)
		if len(provenance.FieldPath) > MaxLocatorBytes || len(provenance.Locator) > MaxLocatorBytes || secretSemanticName(provenance.FieldPath) || secretSemanticName(provenance.Locator) {
			return newError(generated.ErrorCodeInputInvalid, targetDraft)
		}
	}
	for _, finding := range findings {
		if !allowedFindingCodes[finding.Code] || finding.Severity != "error" || !finding.Blocking || len(finding.FieldPath) > MaxLocatorBytes || len(finding.Location) > MaxLocatorBytes || len(finding.RelatedIDs) > MaxIdentities || secretSemanticName(finding.FieldPath) || secretSemanticName(finding.Location) {
			return newError(generated.ErrorCodeInputInvalid, targetDraft)
		}
		stringsToCheck = append(stringsToCheck, finding.Code, finding.Severity, finding.RecordKind, string(finding.RecordID), finding.FieldPath, finding.Location)
	}
	for _, value := range stringsToCheck {
		if !utf8.ValidString(value) || len(value) > MaxTextBytes || containsSecretValue(value) {
			return newError(generated.ErrorCodeInputInvalid, targetDraft)
		}
	}
	return nil
}

func validateSemantics(ctx context.Context, candidate DraftCandidate) []Finding {
	var findings []Finding
	if ctx.Err() != nil {
		return findings
	}
	assets := make(map[LocalID]bool)
	nodes := make(map[LocalID]DraftNode)
	allRecords := make(map[LocalID]string)
	identityOwners := make(map[string][]LocalID)
	aliases := make(map[string][]LocalID)
	addresses := make(map[string][]LocalID)
	addRecord := func(kind string, id LocalID) {
		if id == "" {
			findings = append(findings, finding("MISSING_REQUIRED_FIELD", kind, id, "id"))
			return
		}
		if previous, exists := allRecords[id]; exists {
			findings = append(findings, finding("DUPLICATE_RECORD_ID", kind, id, "id", LocalID(previous)))
		} else {
			allRecords[id] = kind
		}
	}
	for _, asset := range candidate.Assets {
		addRecord("asset", asset.ID)
		assets[asset.ID] = true
		if !validAssetKind(asset.Kind) || !validLifecycle(asset.Lifecycle) {
			findings = append(findings, finding("UNSUPPORTED_VALUE", "asset", asset.ID, "kind"))
		}
		for _, identity := range asset.Identities {
			if !validIdentityKind(identity.Kind) {
				findings = append(findings, finding("IDENTITY_UNSUPPORTED", "asset", asset.ID, "identities"))
				continue
			}
			if identity.Value == "" {
				findings = append(findings, finding("MISSING_REQUIRED_FIELD", "asset", asset.ID, "identities"))
				continue
			}
			if identity.Quarantined {
				findings = append(findings, finding("IDENTITY_QUARANTINED", "asset", asset.ID, "identities"))
			}
			if asset.Kind == AssetPhysical && identity.Kind == "hardware-serial" {
				identityOwners[identity.Kind+"\x00"+identity.Value] = append(identityOwners[identity.Kind+"\x00"+identity.Value], asset.ID)
			}
		}
		for _, fact := range asset.HardwareFacts {
			if !validFact(fact) {
				findings = append(findings, finding("INVALID_CAPACITY", "asset", asset.ID, "hardwareFacts", fact.ID))
			}
		}
	}
	for _, owners := range identityOwners {
		if len(owners) > 1 {
			for _, owner := range owners {
				findings = append(findings, finding("DUPLICATE_IDENTITY", "asset", owner, "identities", owners...))
			}
		}
	}
	for _, node := range candidate.Nodes {
		addRecord("node", node.ID)
		nodes[node.ID] = node
		if !assets[node.AssetID] {
			findings = append(findings, finding("MISSING_REFERENCE", "node", node.ID, "assetId", node.AssetID))
		}
	}
	for _, alias := range candidate.Aliases {
		addRecord("alias", alias.ID)
		aliases[alias.Value] = append(aliases[alias.Value], alias.ID)
		if _, ok := allRecords[alias.TargetID]; !ok {
			findings = append(findings, finding("MISSING_REFERENCE", "alias", alias.ID, "targetId", alias.TargetID))
		}
	}
	for _, ids := range aliases {
		if len(ids) > 1 {
			for _, id := range ids {
				findings = append(findings, finding("DUPLICATE_ALIAS", "alias", id, "value", ids...))
			}
		}
	}
	for _, address := range candidate.Addresses {
		addRecord("address", address.ID)
		addresses[address.Value] = append(addresses[address.Value], address.ID)
		if _, ok := nodes[address.NodeID]; !ok {
			findings = append(findings, finding("MISSING_REFERENCE", "address", address.ID, "nodeId", address.NodeID))
		}
		if _, err := netip.ParseAddr(address.Value); err != nil {
			findings = append(findings, finding("UNSUPPORTED_VALUE", "address", address.ID, "value"))
		}
	}
	for _, ids := range addresses {
		if len(ids) > 1 {
			for _, id := range ids {
				findings = append(findings, finding("DUPLICATE_ADDRESS", "address", id, "value", ids...))
			}
		}
	}
	for _, observation := range candidate.Observations {
		addRecord("observation", observation.ID)
		if _, ok := allRecords[observation.SubjectID]; !ok {
			findings = append(findings, finding("MISSING_REFERENCE", "observation", observation.ID, "subjectId", observation.SubjectID))
		}
	}
	for _, provenance := range candidate.Provenance {
		if allRecords[provenance.RecordID] != provenance.RecordKind {
			findings = append(findings, finding("MISSING_REFERENCE", "provenance", provenance.RecordID, "recordId"))
		}
	}
	findings = append(findings, cycleFindings(nodes)...)
	return findings
}

func cycleFindings(nodes map[LocalID]DraftNode) []Finding {
	var findings []Finding
	state := make(map[LocalID]uint8)
	var visit func(LocalID)
	visit = func(id LocalID) {
		if state[id] == 2 {
			return
		}
		if state[id] == 1 {
			findings = append(findings, finding("REFERENCE_CYCLE", "node", id, "parentId"))
			return
		}
		state[id] = 1
		if parent := nodes[id].ParentID; parent != "" {
			if _, ok := nodes[parent]; !ok {
				findings = append(findings, finding("MISSING_REFERENCE", "node", id, "parentId", parent))
			} else {
				visit(parent)
			}
		}
		state[id] = 2
	}
	ids := make([]LocalID, 0, len(nodes))
	for id := range nodes {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		visit(id)
	}
	return findings
}

func finding(code, kind string, id LocalID, field string, related ...LocalID) Finding {
	return Finding{Code: code, Severity: "error", Blocking: true, RecordKind: kind, RecordID: id, FieldPath: field, Location: "records/" + string(id) + "/" + field, RelatedIDs: related}
}

func validAssetKind(value AssetKind) bool {
	return value == AssetPhysical || value == AssetVirtual || value == AssetNetwork || value == AssetStorage || value == AssetOther
}
func validLifecycle(value AssetLifecycle) bool {
	return value == LifecycleCandidate || value == LifecycleAvailable || value == LifecycleQuarantined || value == LifecycleRetired
}
func validIdentityKind(value string) bool {
	switch value {
	case "hardware-serial", "installation", "machine", "virtual-instance", "ssh-host-key-fingerprint":
		return true
	}
	return false
}
func validFact(fact DraftHardwareFact) bool {
	count := fact.Kind == "cpu-physical-cores" || fact.Kind == "cpu-logical-threads"
	capacity := fact.Kind == "memory-capacity" || fact.Kind == "storage-capacity"
	text := fact.Kind == "manufacturer" || fact.Kind == "model" || fact.Kind == "chassis" || fact.Kind == "firmware-version" || fact.Kind == "cpu-architecture" || fact.Kind == "cpu-model"
	if fact.IntegerValue != nil && *fact.IntegerValue < 0 {
		return false
	}
	if count {
		return fact.IntegerValue != nil && fact.TextValue == nil && fact.Unit == "count"
	}
	if capacity {
		return fact.IntegerValue != nil && fact.TextValue == nil && fact.Unit == "bytes"
	}
	if text {
		return fact.IntegerValue == nil && fact.TextValue != nil && strings.TrimSpace(*fact.TextValue) != "" && fact.Unit == ""
	}
	return false
}
