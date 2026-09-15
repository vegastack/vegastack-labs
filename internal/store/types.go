package store

import (
	"context"
	"time"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

// RevisionToken binds optimistic writes to both the current desired-state
// revision and the active recovery authority.
type RevisionToken struct {
	StateRevision int64
	RecoveryEpoch int64
}

type GateDraftRequest struct {
	EvidenceID, GateID, SubjectID, DefinitionVersion, EvaluatorVersion string
	SourceKind, ProofClass                                             string
	SupersedesEvidenceID, RevokesEvidenceID                            *string
	ArtifactDigest                                                     string
	Bundle                                                             generated.GateEvidenceBundle
	Expected                                                           RevisionToken
	KeyDigest, RequestDigest                                           string
	Attribution                                                        audit.Attribution
}

type GateDraft struct {
	DraftID, EvidenceID, GateID, SubjectID, DefinitionVersion, EvaluatorVersion string
	SourceKind, ProofClass                                                      string
	SupersedesEvidenceID, RevokesEvidenceID                                     *string
	ArtifactDigest, BundleDigest                                                string
	Bundle                                                                      generated.GateEvidenceBundle
	StateRevision, RecoveryEpoch                                                int64
	HumanID, CreatedAt                                                          string
}

type GateApplyRequest struct {
	DraftID, EvidenceID, GateID, SubjectID     string
	Expected                                   RevisionToken
	PlanID, PlanDigest, RunID, StepID, LeaseID string
	DeclarationID                              string
	DeclarationRevision                        int64
	ReleaseBuildID, ToolVersion                string
	ExpiresAt                                  string
	SourceKind, ProofClass, Status             string
	SupersedesEvidenceID, RevokesEvidenceID    *string
	KeyDigest, RequestDigest                   string
	Attribution                                audit.Attribution
}

type ProfileApplyRequest struct {
	BindingID                                  string
	Scope                                      GateAppliedProfile
	Expected                                   RevisionToken
	PlanID, PlanDigest, RunID, StepID, LeaseID string
	DeclarationID                              string
	DeclarationRevision                        int64
	KeyDigest, RequestDigest                   string
	Attribution                                audit.Attribution
}

type ProfileDraftRequest struct {
	BindingID                string
	Scope                    GateAppliedProfile
	Expected                 RevisionToken
	KeyDigest, RequestDigest string
	Attribution              audit.Attribution
}

type ProfileDraft struct {
	BindingID                    string
	Scope                        GateAppliedProfile
	ScopeDigest                  string
	StateRevision, RecoveryEpoch int64
	HumanID, CreatedAt           string
}

type GateAppliedProfile struct {
	ProfileID, ProfileVersion, PolicyID, PolicyVersion string
	Capabilities                                       []string
	StateRevision, RecoveryEpoch                       int64
}

// Commit describes the durable result of one intent transaction.
type Commit struct {
	Changed       bool
	StateRevision int64
	RecoveryEpoch int64
}

type DatabaseMode string

const (
	DatabaseReady    DatabaseMode = "ready"
	DatabaseSafeMode DatabaseMode = "safe-mode"
)

type IntegrityStatus string

const (
	IntegrityUnknown  IntegrityStatus = "unknown"
	IntegrityVerified IntegrityStatus = "verified"
	IntegrityFailed   IntegrityStatus = "failed"
)

type OpenMode string

const (
	OpenExisting  OpenMode = "open-existing"
	InitializeNew OpenMode = "initialize-new"
)

// Health deliberately contains no database path, file identity, SQL text, or
// raw underlying error.
type Health struct {
	Mode                 DatabaseMode
	SchemaVersion        uint64
	SQLiteVersion        string
	Revision             RevisionToken
	MutationEnabled      bool
	RecoveryPending      bool
	IntegrityStatus      IntegrityStatus
	LastIntegrityCheckAt *time.Time
	SafeModeReason       string
}

// ReadTx and IntentTx are intentionally opaque outside this package. Typed
// repositories implemented in internal/store receive the private handles in
// later migrations without exposing database/sql.
type ReadTx struct {
	handle any
}

type IntentTx struct {
	handle any
}

type IntentStore interface {
	Read(context.Context, func(ReadTx) error) error
	WriteIntent(context.Context, *RevisionToken, func(IntentTx) error) (Commit, error)
}

type Config struct {
	DatabasePath string
	Mode         OpenMode
	BusyTimeout  time.Duration
	ExpectedUID  uint32
	ToolVersion  string
	BuildVersion string
	Clock        func() time.Time
	Filesystem   FilesystemInspector
	Recovery     MigrationRecovery
}
