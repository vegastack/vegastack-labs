// Package inventory defines provider-neutral, inert inventory draft contracts.
// Drafts in this package are validation artifacts only; none of the types expose
// a transition to declared, trusted, qualified, admitted, or effective state.
package inventory

import (
	"context"
	"time"

	"github.com/vegastack/vegastack-labs/internal/audit"
)

const (
	MaxInputBytes       = 4 << 20
	MaxJSONDepth        = 32
	MaxPrimaryRecords   = 4096
	MaxHardwareFacts    = 16384
	MaxProvenance       = 32768
	MaxIdentities       = 64
	MaxFactsPerAsset    = 64
	MaxTokenBytes       = 128
	MaxLocatorBytes     = 256
	MaxTextBytes        = 1024
	MaxIdempotencyBytes = 256
	MaxQueryLimit       = 256
)

type DraftID string
type LocalID string

type DraftValidationStatus string

const (
	DraftValid   DraftValidationStatus = "valid"
	DraftBlocked DraftValidationStatus = "blocked"
)

type AssetKind string

const (
	AssetPhysical AssetKind = "physical"
	AssetVirtual  AssetKind = "virtual"
	AssetNetwork  AssetKind = "network"
	AssetStorage  AssetKind = "storage"
	AssetOther    AssetKind = "other"
)

type AssetLifecycle string

const (
	LifecycleCandidate   AssetLifecycle = "candidate"
	LifecycleAvailable   AssetLifecycle = "available"
	LifecycleQuarantined AssetLifecycle = "quarantined"
	LifecycleRetired     AssetLifecycle = "retired"
)

type SourceDescriptor struct {
	Kind           string    `json:"kind"`
	AdapterKind    string    `json:"adapterKind"`
	AdapterVersion string    `json:"adapterVersion"`
	SourceRevision string    `json:"sourceRevision"`
	Digest         string    `json:"digest"`
	CapturedAt     time.Time `json:"capturedAt"`
}

type DraftCandidate struct {
	Source       SourceDescriptor   `json:"source"`
	Assets       []DraftAsset       `json:"assets"`
	Nodes        []DraftNode        `json:"nodes"`
	Aliases      []DraftAlias       `json:"aliases"`
	Addresses    []DraftAddress     `json:"addresses"`
	Observations []DraftObservation `json:"observations"`
	Provenance   []FieldProvenance  `json:"provenance"`
}

type DecodedCandidate struct {
	Candidate DraftCandidate
	Findings  []Finding
}

type DraftAsset struct {
	ID            LocalID             `json:"id"`
	Kind          AssetKind           `json:"kind"`
	Lifecycle     AssetLifecycle      `json:"lifecycle"`
	Identities    []DraftIdentity     `json:"identities"`
	HardwareFacts []DraftHardwareFact `json:"hardwareFacts"`
}

type DraftIdentity struct {
	Kind        string `json:"kind"`
	Value       string `json:"value"`
	Quarantined bool   `json:"quarantined"`
}

type DraftNode struct {
	ID       LocalID `json:"id"`
	AssetID  LocalID `json:"assetId"`
	ParentID LocalID `json:"parentId"`
}

type DraftAlias struct {
	ID       LocalID `json:"id"`
	TargetID LocalID `json:"targetId"`
	Value    string  `json:"value"`
}

type DraftAddress struct {
	ID     LocalID `json:"id"`
	NodeID LocalID `json:"nodeId"`
	Value  string  `json:"value"`
}

type DraftObservation struct {
	ID         LocalID   `json:"id"`
	SubjectID  LocalID   `json:"subjectId"`
	Kind       string    `json:"kind"`
	Value      string    `json:"value"`
	ObservedAt time.Time `json:"observedAt"`
}

type DraftHardwareFact struct {
	ID           LocalID `json:"id"`
	Kind         string  `json:"kind"`
	IntegerValue *int64  `json:"integerValue"`
	TextValue    *string `json:"textValue"`
	Unit         string  `json:"unit"`
}

type FieldProvenance struct {
	RecordKind     string    `json:"recordKind"`
	RecordID       LocalID   `json:"recordId"`
	FieldPath      string    `json:"fieldPath"`
	Locator        string    `json:"locator"`
	CapturedAt     time.Time `json:"capturedAt"`
	AdapterVersion string    `json:"adapterVersion"`
	ValueStatus    string    `json:"valueStatus"`
}

type Finding struct {
	Code       string    `json:"code"`
	Severity   string    `json:"severity"`
	Blocking   bool      `json:"blocking"`
	RecordKind string    `json:"recordKind"`
	RecordID   LocalID   `json:"recordId"`
	FieldPath  string    `json:"fieldPath"`
	Location   string    `json:"location"`
	RelatedIDs []LocalID `json:"relatedIds"`
}

type DraftCounts struct {
	Assets        int `json:"assets"`
	Nodes         int `json:"nodes"`
	Aliases       int `json:"aliases"`
	Addresses     int `json:"addresses"`
	Observations  int `json:"observations"`
	HardwareFacts int `json:"hardwareFacts"`
	Provenance    int `json:"provenance"`
	Findings      int `json:"findings"`
}

type DraftRef struct {
	ID       DraftID `json:"id"`
	Revision int64   `json:"revision"`
}

type DraftSummary struct {
	Ref              DraftRef              `json:"ref"`
	ValidationStatus DraftValidationStatus `json:"validationStatus"`
	ContentDigest    string                `json:"contentDigest"`
	CreatedAt        time.Time             `json:"createdAt"`
	Counts           DraftCounts           `json:"counts"`
}

type DraftRecord struct {
	Kind    string  `json:"kind"`
	LocalID LocalID `json:"localId"`
}

type PersistedDraft struct {
	Ref              DraftRef
	ValidationStatus DraftValidationStatus
	Source           SourceDescriptor
	Assets           []DraftAsset
	Nodes            []DraftNode
	Aliases          []DraftAlias
	Addresses        []DraftAddress
	Observations     []DraftObservation
	Provenance       []FieldProvenance
	Findings         []Finding
	Counts           DraftCounts
	ContentDigest    string
	CreatedAt        time.Time
}

type DraftListQuery struct {
	AfterCreatedAt time.Time
	AfterDraftID   DraftID
	AfterRevision  int64
	Limit          int
	Sort           string
}

type RecordListQuery struct {
	AfterKind    string
	AfterLocalID LocalID
	Limit        int
	Sort         string
}

type CanonicalDraftSnapshot struct {
	Kind             string                `json:"kind"`
	Ref              DraftRef              `json:"ref"`
	ValidationStatus DraftValidationStatus `json:"validationStatus"`
	Source           SourceDescriptor      `json:"source"`
	Assets           []DraftAsset          `json:"assets"`
	Nodes            []DraftNode           `json:"nodes"`
	Aliases          []DraftAlias          `json:"aliases"`
	Addresses        []DraftAddress        `json:"addresses"`
	Observations     []DraftObservation    `json:"observations"`
	Provenance       []FieldProvenance     `json:"provenance"`
	Findings         []Finding             `json:"findings"`
	ContentDigest    string                `json:"contentDigest"`
}

type NormalizedDraft struct {
	Candidate        DraftCandidate
	ValidationStatus DraftValidationStatus
	ContentDigest    string
	Counts           DraftCounts
	Findings         []Finding
}

type PutDraftRequest struct {
	ExpectedStateRevision *int64
	IdempotencyKeyDigest  string
	CandidateDigest       string
	DraftID               DraftID
	Draft                 NormalizedDraft
	Event                 audit.EventDraft
	Destinations          []audit.OutboxRequirement
}

type PutDraftResult struct {
	Ref                 DraftRef
	Created             bool
	CommitStateRevision int64
	RecoveryEpoch       int64
	EventID             audit.EventID
}

type DraftRepository interface {
	Put(context.Context, PutDraftRequest) (PutDraftResult, error)
	Get(context.Context, DraftRef) (PersistedDraft, error)
	ListDrafts(context.Context, DraftListQuery) ([]DraftSummary, error)
	ListRecords(context.Context, DraftRef, RecordListQuery) ([]DraftRecord, error)
}

type ExportProjection interface {
	SnapshotDraft(context.Context, DraftRef) (CanonicalDraftSnapshot, error)
}

type ImportRequest struct {
	IdempotencyKey        string
	CorrelationID         string
	ExpectedStateRevision *int64
	Decoded               DecodedCandidate
}

type ImportResult struct {
	DraftID          DraftID
	DraftRevision    int64
	ValidationStatus DraftValidationStatus
	SourceDigest     string
	ContentDigest    string
	StateRevision    int64
	RecoveryEpoch    int64
	EventID          audit.EventID
	Created          bool
	Counts           DraftCounts
	Findings         []Finding
}

type ImportService interface {
	ValidateAndStore(context.Context, ImportRequest) (ImportResult, error)
}

type IDGenerator func() (DraftID, error)
