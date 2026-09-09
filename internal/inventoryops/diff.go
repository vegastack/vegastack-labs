package inventoryops

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"time"

	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/inventory"
)

type Lineage struct {
	SourceKind     string
	AdapterKind    string
	AdapterVersion string
}

type DiffSnapshotRequest struct {
	Scope     authorization.ReadScope
	Candidate *inventory.DraftRef
	Lineage   Lineage
}

type ResolvedDiffSnapshot struct {
	Candidate     *inventory.CanonicalDraftSnapshot
	Baseline      inventory.CanonicalDraftSnapshot
	StateRevision int64
	RecoveryEpoch int64
}

type DiffRepository interface {
	ResolveDiffSnapshot(context.Context, DiffSnapshotRequest) (ResolvedDiffSnapshot, error)
}

type Candidate struct {
	Kind  string
	Draft *inventory.DraftRef
	File  *DecoderRequest
}

type DiffRequest struct {
	Scope     authorization.ReadScope
	Candidate Candidate
}

type DiffResult struct {
	CandidateKind   string
	CandidateDraft  *inventory.DraftRef
	CandidateDigest string
	BaselineKind    string
	BaselineDraft   inventory.DraftRef
	StateRevision   int64
	RecoveryEpoch   int64
	Counts          generated.InventoryDiffCounts
	Records         []generated.InventoryDiffRecord
	Findings        []inventory.Finding
}

type DiffService struct {
	repository DiffRepository
	decoders   DecoderRegistry
}

func NewDiffService(repository DiffRepository, decoders DecoderRegistry) (*DiffService, error) {
	if repository == nil || decoders == nil {
		return nil, failure.New(generated.ErrorCodeInputInvalid, "inventory-diff-service", false)
	}
	return &DiffService{repository: repository, decoders: decoders}, nil
}

func (service *DiffService) Diff(ctx context.Context, request DiffRequest) (DiffResult, error) {
	if service == nil || service.repository == nil || service.decoders == nil || ctx.Err() != nil {
		return DiffResult{}, failure.New(generated.ErrorCodeInterrupted, "inventory-diff", false)
	}
	var candidate inventory.CanonicalDraftSnapshot
	var query DiffSnapshotRequest
	query.Scope = request.Scope
	switch request.Candidate.Kind {
	case "draft":
		if request.Candidate.Draft == nil || request.Candidate.File != nil || request.Candidate.Draft.ID == "" || request.Candidate.Draft.Revision < 1 {
			return DiffResult{}, failure.New(generated.ErrorCodeInputInvalid, "inventory-diff-candidate", false)
		}
		ref := *request.Candidate.Draft
		query.Candidate = &ref
	case "file":
		if request.Candidate.Draft != nil || request.Candidate.File == nil {
			return DiffResult{}, failure.New(generated.ErrorCodeInputInvalid, "inventory-diff-candidate", false)
		}
		decoded, err := service.decoders.Decode(ctx, *request.Candidate.File)
		if err != nil {
			return DiffResult{}, err
		}
		normalized, err := inventory.NormalizeAndValidate(ctx, decoded)
		if err != nil {
			return DiffResult{}, sanitizeDomainError(err, "inventory-diff-candidate")
		}
		candidate = snapshotFromNormalized(normalized)
		query.Lineage = lineage(candidate.Source)
	default:
		return DiffResult{}, failure.New(generated.ErrorCodeInputInvalid, "inventory-diff-candidate", false)
	}
	resolved, err := service.repository.ResolveDiffSnapshot(ctx, query)
	if err != nil {
		return DiffResult{}, sanitizeDomainError(err, "inventory-diff-baseline")
	}
	if query.Candidate != nil {
		if resolved.Candidate == nil {
			return DiffResult{}, failure.New(generated.ErrorCodeIntegrityFailure, "inventory-diff-candidate", false)
		}
		candidate = *resolved.Candidate
	}
	if resolved.StateRevision < 0 || resolved.RecoveryEpoch < 0 || resolved.Baseline.Kind != "draft" || candidate.ContentDigest == "" || resolved.Baseline.ContentDigest == "" || lineage(candidate.Source) != lineage(resolved.Baseline.Source) {
		return DiffResult{}, failure.New(generated.ErrorCodeIntegrityFailure, "inventory-diff-snapshot", false)
	}
	if ctx.Err() != nil {
		return DiffResult{}, failure.New(generated.ErrorCodeInterrupted, "inventory-diff", false)
	}
	records, counts := compareRecords(flatten(candidate), flatten(resolved.Baseline))
	var candidateRef *inventory.DraftRef
	if request.Candidate.Kind == "draft" {
		value := candidate.Ref
		candidateRef = &value
	}
	return DiffResult{CandidateKind: request.Candidate.Kind, CandidateDraft: candidateRef, CandidateDigest: candidate.ContentDigest,
		BaselineKind: "draft", BaselineDraft: resolved.Baseline.Ref, StateRevision: resolved.StateRevision, RecoveryEpoch: resolved.RecoveryEpoch,
		Counts: counts, Records: records, Findings: append([]inventory.Finding(nil), candidate.Findings...)}, nil
}

func snapshotFromNormalized(value inventory.NormalizedDraft) inventory.CanonicalDraftSnapshot {
	return inventory.CanonicalDraftSnapshot{Kind: "draft", ValidationStatus: value.ValidationStatus, Source: value.Candidate.Source,
		Assets: value.Candidate.Assets, Nodes: value.Candidate.Nodes, Aliases: value.Candidate.Aliases, Addresses: value.Candidate.Addresses,
		Observations: value.Candidate.Observations, Provenance: value.Candidate.Provenance, Findings: value.Findings, ContentDigest: value.ContentDigest}
}

func lineage(source inventory.SourceDescriptor) Lineage {
	return Lineage{SourceKind: source.Kind, AdapterKind: source.AdapterKind, AdapterVersion: source.AdapterVersion}
}

func sanitizeDomainError(err error, target string) error {
	if stable, ok := failure.As(err); ok {
		return failure.New(stable.Code, target, stable.Retryable)
	}
	if coded, ok := err.(interface{ Code() string }); ok {
		switch coded.Code() {
		case generated.ErrorCodeAuthorizationDenied, generated.ErrorCodeResourceNotFound, generated.ErrorCodeStateConflict, generated.ErrorCodeRecoveryEpochMismatch, generated.ErrorCodePrerequisiteBlocked, generated.ErrorCodeInterrupted, generated.ErrorCodeIntegrityFailure, generated.ErrorCodeDependencyUnavailable, generated.ErrorCodeInputInvalid:
			return failure.New(coded.Code(), target, false)
		}
	}
	if typed, ok := err.(*inventory.Error); ok {
		switch typed.Code {
		case generated.ErrorCodeInputInvalid, generated.ErrorCodeInterrupted, generated.ErrorCodeSchemaUnsupported:
			return failure.New(typed.Code, target, false)
		}
	}
	return failure.New(generated.ErrorCodeDependencyUnavailable, target, false)
}

type flatField struct{ fieldPath, value string }
type flatRecord struct {
	kind, id string
	fields   []flatField
}

func flatten(snapshot inventory.CanonicalDraftSnapshot) []flatRecord {
	var records []flatRecord
	for _, asset := range snapshot.Assets {
		fields := []flatField{{"kind", scalar(string(asset.Kind))}, {"lifecycle", scalar(string(asset.Lifecycle))}}
		for index, identity := range asset.Identities {
			prefix := indexed("identities", index)
			fields = append(fields, flatField{prefix + ".kind", scalar(identity.Kind)}, flatField{prefix + ".value", scalar(identity.Value)}, flatField{prefix + ".quarantined", scalar(identity.Quarantined)})
		}
		for index, fact := range asset.HardwareFacts {
			prefix := indexed("hardwareFacts", index)
			fields = append(fields, flatField{prefix + ".id", scalar(string(fact.ID))}, flatField{prefix + ".kind", scalar(fact.Kind)}, flatField{prefix + ".integerValue", nullableInt(fact.IntegerValue)}, flatField{prefix + ".textValue", nullableString(fact.TextValue)}, flatField{prefix + ".unit", scalar(fact.Unit)})
		}
		records = append(records, flatRecord{"asset", string(asset.ID), fields})
	}
	for _, value := range snapshot.Nodes {
		records = append(records, flatRecord{"node", string(value.ID), []flatField{{"assetId", scalar(string(value.AssetID))}, {"parentId", scalar(string(value.ParentID))}}})
	}
	for _, value := range snapshot.Aliases {
		records = append(records, flatRecord{"alias", string(value.ID), []flatField{{"targetId", scalar(string(value.TargetID))}, {"value", scalar(value.Value)}}})
	}
	for _, value := range snapshot.Addresses {
		records = append(records, flatRecord{"address", string(value.ID), []flatField{{"nodeId", scalar(string(value.NodeID))}, {"value", scalar(value.Value)}}})
	}
	for _, value := range snapshot.Observations {
		records = append(records, flatRecord{"observation", string(value.ID), []flatField{{"subjectId", scalar(string(value.SubjectID))}, {"kind", scalar(value.Kind)}, {"value", scalar(value.Value)}, {"observedAt", scalar(value.ObservedAt.UTC().Format(time.RFC3339Nano))}}})
	}
	for _, value := range snapshot.Provenance {
		identity := scalar(value.RecordKind) + "\x00" + scalar(string(value.RecordID)) + "\x00" + scalar(value.FieldPath) + "\x00" + scalar(value.Locator)
		sum := sha256.Sum256([]byte(identity))
		id := "provenance:" + hex.EncodeToString(sum[:])
		records = append(records, flatRecord{"provenance", id, []flatField{{"recordKind", scalar(value.RecordKind)}, {"recordId", scalar(string(value.RecordID))}, {"fieldPath", scalar(value.FieldPath)}, {"locator", scalar(value.Locator)}, {"capturedAt", scalar(value.CapturedAt.UTC().Format(time.RFC3339Nano))}, {"adapterVersion", scalar(value.AdapterVersion)}, {"valueStatus", scalar(value.ValueStatus)}}})
	}
	for index := range records {
		sort.Slice(records[index].fields, func(i, j int) bool { return records[index].fields[i].fieldPath < records[index].fields[j].fieldPath })
	}
	sort.Slice(records, func(i, j int) bool {
		left, right := recordRank(records[i].kind), recordRank(records[j].kind)
		if left != right {
			return left < right
		}
		return records[i].id < records[j].id
	})
	return records
}

func compareRecords(candidate, baseline []flatRecord) ([]generated.InventoryDiffRecord, generated.InventoryDiffCounts) {
	result := make([]generated.InventoryDiffRecord, 0, len(candidate)+len(baseline))
	var counts generated.InventoryDiffCounts
	for left, right := 0, 0; left < len(candidate) || right < len(baseline); {
		if right == len(baseline) || (left < len(candidate) && lessRecord(candidate[left], baseline[right])) {
			result = append(result, oneSided(candidate[left], "added", false))
			counts.Added++
			left++
			continue
		}
		if left == len(candidate) || lessRecord(baseline[right], candidate[left]) {
			result = append(result, oneSided(baseline[right], "removed", true))
			counts.Removed++
			right++
			continue
		}
		changes := compareFields(candidate[left].fields, baseline[right].fields)
		change := "unchanged"
		if len(changes) == 0 {
			counts.Unchanged++
		} else {
			change = "changed"
			counts.Changed++
		}
		result = append(result, generated.InventoryDiffRecord{Change: change, RecordKind: candidate[left].kind, LocalID: candidate[left].id, Fields: changes})
		left++
		right++
	}
	return result, counts
}

func compareFields(candidate, baseline []flatField) []generated.InventoryFieldChange {
	var result []generated.InventoryFieldChange
	for left, right := 0, 0; left < len(candidate) || right < len(baseline); {
		if right == len(baseline) || (left < len(candidate) && candidate[left].fieldPath < baseline[right].fieldPath) {
			value := candidate[left].value
			result = append(result, generated.InventoryFieldChange{Path: candidate[left].fieldPath, After: &value})
			left++
			continue
		}
		if left == len(candidate) || baseline[right].fieldPath < candidate[left].fieldPath {
			value := baseline[right].value
			result = append(result, generated.InventoryFieldChange{Path: baseline[right].fieldPath, Before: &value})
			right++
			continue
		}
		if candidate[left].value != baseline[right].value {
			before, after := baseline[right].value, candidate[left].value
			result = append(result, generated.InventoryFieldChange{Path: candidate[left].fieldPath, Before: &before, After: &after})
		}
		left++
		right++
	}
	return result
}

func oneSided(record flatRecord, change string, before bool) generated.InventoryDiffRecord {
	fields := make([]generated.InventoryFieldChange, 0, len(record.fields))
	for _, field := range record.fields {
		value := field.value
		item := generated.InventoryFieldChange{Path: field.fieldPath}
		if before {
			item.Before = &value
		} else {
			item.After = &value
		}
		fields = append(fields, item)
	}
	return generated.InventoryDiffRecord{Change: change, RecordKind: record.kind, LocalID: record.id, Fields: fields}
}
func lessRecord(left, right flatRecord) bool {
	lr, rr := recordRank(left.kind), recordRank(right.kind)
	return lr < rr || (lr == rr && left.id < right.id)
}
func recordRank(kind string) int {
	switch kind {
	case "asset":
		return 0
	case "node":
		return 1
	case "alias":
		return 2
	case "address":
		return 3
	case "observation":
		return 4
	default:
		return 5
	}
}
func indexed(name string, index int) string {
	raw, _ := json.Marshal(index)
	return name + "[" + string(raw) + "]"
}
func scalar(value any) string { raw, _ := json.Marshal(value); return string(raw) }
func nullableString(value *string) string {
	if value == nil {
		return "null"
	}
	return scalar(*value)
}
func nullableInt(value *int64) string {
	if value == nil {
		return "null"
	}
	return scalar(*value)
}
