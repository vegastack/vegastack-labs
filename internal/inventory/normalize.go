package inventory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

func NormalizeAndValidate(ctx context.Context, decoded DecodedCandidate) (NormalizedDraft, error) {
	if ctx.Err() != nil {
		return NormalizedDraft{}, newError(generated.ErrorCodeInterrupted, targetContext)
	}
	candidate := cloneCandidate(decoded.Candidate)
	if err := validateBoundsAndSecrets(candidate, decoded.Findings); err != nil {
		return NormalizedDraft{}, err
	}
	normalizeCandidate(&candidate)
	findings := append([]Finding(nil), decoded.Findings...)
	findings = append(findings, validateSemantics(ctx, candidate)...)
	if ctx.Err() != nil {
		return NormalizedDraft{}, newError(generated.ErrorCodeInterrupted, targetContext)
	}
	findings = normalizeFindings(findings)
	status := DraftValid
	if len(findings) > 0 {
		status = DraftBlocked
	}
	counts := countCandidate(candidate, len(findings))
	digestCandidate := cloneCandidate(candidate)
	digestCandidate.Source.Digest = ""
	canonical, err := json.Marshal(struct {
		Candidate DraftCandidate `json:"candidate"`
		Findings  []Finding      `json:"findings"`
	}{digestCandidate, findings})
	if err != nil {
		return NormalizedDraft{}, newError(generated.ErrorCodeInputInvalid, targetDraft)
	}
	digest := sha256.Sum256(canonical)
	return NormalizedDraft{Candidate: candidate, ValidationStatus: status, ContentDigest: "sha256:" + hex.EncodeToString(digest[:]), Counts: counts, Findings: findings}, nil
}

func cloneCandidate(candidate DraftCandidate) DraftCandidate {
	candidate.Assets = slices.Clone(candidate.Assets)
	for index := range candidate.Assets {
		candidate.Assets[index].Identities = slices.Clone(candidate.Assets[index].Identities)
		candidate.Assets[index].HardwareFacts = slices.Clone(candidate.Assets[index].HardwareFacts)
	}
	candidate.Nodes = slices.Clone(candidate.Nodes)
	candidate.Aliases = slices.Clone(candidate.Aliases)
	candidate.Addresses = slices.Clone(candidate.Addresses)
	candidate.Observations = slices.Clone(candidate.Observations)
	candidate.Provenance = slices.Clone(candidate.Provenance)
	return candidate
}

func normalizeCandidate(candidate *DraftCandidate) {
	candidate.Source.Kind = strings.TrimSpace(candidate.Source.Kind)
	candidate.Source.AdapterKind = strings.TrimSpace(candidate.Source.AdapterKind)
	candidate.Source.AdapterVersion = strings.TrimSpace(candidate.Source.AdapterVersion)
	candidate.Source.SourceRevision = strings.TrimSpace(candidate.Source.SourceRevision)
	candidate.Source.CapturedAt = candidate.Source.CapturedAt.UTC().Truncate(0)
	for assetIndex := range candidate.Assets {
		asset := &candidate.Assets[assetIndex]
		asset.ID = LocalID(strings.TrimSpace(string(asset.ID)))
		for identityIndex := range asset.Identities {
			identity := &asset.Identities[identityIndex]
			identity.Kind = strings.TrimSpace(identity.Kind)
			identity.Value = strings.TrimSpace(identity.Value)
			if asset.Kind == AssetPhysical && identity.Kind == "hardware-serial" {
				identity.Value = strings.ToUpper(identity.Value)
			}
		}
		for factIndex := range asset.HardwareFacts {
			fact := &asset.HardwareFacts[factIndex]
			fact.ID = LocalID(strings.TrimSpace(string(fact.ID)))
			fact.Kind = strings.TrimSpace(fact.Kind)
			fact.Unit = strings.TrimSpace(fact.Unit)
			if fact.TextValue != nil {
				normalized := strings.TrimSpace(*fact.TextValue)
				fact.TextValue = &normalized
			}
		}
		sort.Slice(asset.Identities, func(i, j int) bool {
			return asset.Identities[i].Kind+"\x00"+asset.Identities[i].Value < asset.Identities[j].Kind+"\x00"+asset.Identities[j].Value
		})
		sort.Slice(asset.HardwareFacts, func(i, j int) bool {
			return canonicalSortKey(asset.HardwareFacts[i]) < canonicalSortKey(asset.HardwareFacts[j])
		})
	}
	for index := range candidate.Nodes {
		candidate.Nodes[index].ID = trimID(candidate.Nodes[index].ID)
		candidate.Nodes[index].AssetID = trimID(candidate.Nodes[index].AssetID)
		candidate.Nodes[index].ParentID = trimID(candidate.Nodes[index].ParentID)
	}
	for index := range candidate.Aliases {
		candidate.Aliases[index].ID = trimID(candidate.Aliases[index].ID)
		candidate.Aliases[index].TargetID = trimID(candidate.Aliases[index].TargetID)
		candidate.Aliases[index].Value = strings.ToLower(strings.TrimSpace(candidate.Aliases[index].Value))
	}
	for index := range candidate.Addresses {
		candidate.Addresses[index].ID = trimID(candidate.Addresses[index].ID)
		candidate.Addresses[index].NodeID = trimID(candidate.Addresses[index].NodeID)
		value := strings.TrimSpace(candidate.Addresses[index].Value)
		if address, err := netip.ParseAddr(value); err == nil {
			value = address.String()
		}
		candidate.Addresses[index].Value = value
	}
	for index := range candidate.Observations {
		observation := &candidate.Observations[index]
		observation.ID = trimID(observation.ID)
		observation.SubjectID = trimID(observation.SubjectID)
		observation.Kind = strings.TrimSpace(observation.Kind)
		observation.Value = strings.TrimSpace(observation.Value)
		observation.ObservedAt = observation.ObservedAt.UTC().Truncate(0)
		if observation.Kind == "mac-address" {
			if value, err := net.ParseMAC(observation.Value); err == nil {
				observation.Value = strings.ToLower(value.String())
			}
		}
	}
	for index := range candidate.Provenance {
		provenance := &candidate.Provenance[index]
		provenance.RecordKind = strings.TrimSpace(provenance.RecordKind)
		provenance.RecordID = trimID(provenance.RecordID)
		provenance.FieldPath = strings.TrimSpace(provenance.FieldPath)
		provenance.Locator = strings.TrimSpace(provenance.Locator)
		provenance.CapturedAt = provenance.CapturedAt.UTC().Truncate(0)
		provenance.AdapterVersion = strings.TrimSpace(provenance.AdapterVersion)
		provenance.ValueStatus = strings.TrimSpace(provenance.ValueStatus)
	}
	sort.Slice(candidate.Assets, func(i, j int) bool {
		return canonicalSortKey(candidate.Assets[i]) < canonicalSortKey(candidate.Assets[j])
	})
	sort.Slice(candidate.Nodes, func(i, j int) bool {
		return canonicalSortKey(candidate.Nodes[i]) < canonicalSortKey(candidate.Nodes[j])
	})
	sort.Slice(candidate.Aliases, func(i, j int) bool {
		return canonicalSortKey(candidate.Aliases[i]) < canonicalSortKey(candidate.Aliases[j])
	})
	sort.Slice(candidate.Addresses, func(i, j int) bool {
		return canonicalSortKey(candidate.Addresses[i]) < canonicalSortKey(candidate.Addresses[j])
	})
	sort.Slice(candidate.Observations, func(i, j int) bool {
		return canonicalSortKey(candidate.Observations[i]) < canonicalSortKey(candidate.Observations[j])
	})
	sort.Slice(candidate.Provenance, func(i, j int) bool {
		return canonicalSortKey(candidate.Provenance[i]) < canonicalSortKey(candidate.Provenance[j])
	})
}

func canonicalSortKey(value any) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}

func trimID(value LocalID) LocalID { return LocalID(strings.TrimSpace(string(value))) }

func countCandidate(candidate DraftCandidate, findings int) DraftCounts {
	facts := 0
	for _, asset := range candidate.Assets {
		facts += len(asset.HardwareFacts)
	}
	return DraftCounts{Assets: len(candidate.Assets), Nodes: len(candidate.Nodes), Aliases: len(candidate.Aliases), Addresses: len(candidate.Addresses), Observations: len(candidate.Observations), HardwareFacts: facts, Provenance: len(candidate.Provenance), Findings: findings}
}

func normalizeFindings(findings []Finding) []Finding {
	for index := range findings {
		findings[index].RecordKind = strings.TrimSpace(findings[index].RecordKind)
		findings[index].RecordID = trimID(findings[index].RecordID)
		findings[index].FieldPath = strings.TrimSpace(findings[index].FieldPath)
		findings[index].Location = strings.TrimSpace(findings[index].Location)
		findings[index].RelatedIDs = slices.Clone(findings[index].RelatedIDs)
		sort.Slice(findings[index].RelatedIDs, func(i, j int) bool { return findings[index].RelatedIDs[i] < findings[index].RelatedIDs[j] })
	}
	sort.Slice(findings, func(i, j int) bool { return findingKey(findings[i]) < findingKey(findings[j]) })
	result := findings[:0]
	for _, finding := range findings {
		if len(result) == 0 || findingKey(result[len(result)-1]) != findingKey(finding) {
			result = append(result, finding)
		}
	}
	return result
}

func findingKey(f Finding) string {
	return rank(recordKindRank, f.RecordKind) + "\x00" + string(f.RecordID) + "\x00" + f.FieldPath + "\x00" + rank(findingCodeRank, f.Code) + "\x00" + strings.Join(localIDs(f.RelatedIDs), "\x00") + "\x00" + f.Location
}
func rank(values map[string]int, value string) string { return string(rune(values[value] + 1)) }
func localIDs(values []LocalID) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = string(value)
	}
	return result
}

var recordKindRank = map[string]int{"asset": 0, "node": 1, "alias": 2, "address": 3, "observation": 4, "hardware-fact": 5, "provenance": 6}
var findingCodeRank = map[string]int{"DUPLICATE_RECORD_ID": 0, "DUPLICATE_IDENTITY": 1, "DUPLICATE_ALIAS": 2, "DUPLICATE_ADDRESS": 3, "MISSING_REFERENCE": 4, "REFERENCE_CYCLE": 5, "IDENTITY_CONFLICT": 6, "IDENTITY_QUARANTINED": 7, "IDENTITY_UNSUPPORTED": 8, "UNSUPPORTED_VALUE": 9, "INVALID_CAPACITY": 10, "MISSING_REQUIRED_FIELD": 11, "PROHIBITED_SECRET_VALUE": 12}

func canonicalTime(value time.Time) bool { return !value.IsZero() }
