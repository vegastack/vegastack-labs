package backup

import (
	"context"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter"
)

const (
	OffsiteProofLocalVerified = "local-verified"
	OffsiteProofClassLive     = "live"
)

// VerifiedCriticalPoint is the immutable, secret-free source admitted for an
// off-site generation. It deliberately carries the canonical local inventory:
// an off-site copy may never select a repository's "latest" snapshot.
type VerifiedCriticalPoint struct {
	PointID, PolicyID, PolicyDigest, RepositoryID, RepositoryClass string
	ManifestDigest, SnapshotID, InventoryDigest, ContentDigest     string
	KeyReferenceID, ResticDigest, DependencyDigest                 string
	ProofStatus, ProofClass, VerificationID                        string
	SourceRevision, StateRevision, RecoveryEpoch                   int64
	ObjectCount, ObjectBytes                                       int64
	ExpectedObjects                                                []ExpectedObject
	ExpectedDependencies                                           []ExpectedDependency
	FullReadValidUntil, FunctionalValidUntil                       time.Time
}

type OffsiteSource interface {
	VerifiedCriticalPoint(context.Context, string) (VerifiedCriticalPoint, error)
}

// OffsitePolicy is a declaration-derived upper bound. Capacity and rule facts
// still come from a separately observed destination; fixture values never
// qualify a live provider.
type OffsitePolicy struct {
	PolicyID, ProfileID, GenerationID, Bucket, Prefix string
	ParentReferenceID, ParentFingerprint              string
	MaximumBytes, MaximumPUTs, MaximumLISTs           int64
	MaximumRetainedGenerations, RuleLimit             int
	RetentionWindow, SessionTTL                       time.Duration
	Clock                                             func() time.Time
}

type GenerationAdmission struct {
	GenerationID, Prefix, RuleDigest        string
	MaximumBytes, MaximumPUTs, MaximumLISTs int64
	ProtectedPrefixes, MutablePrefixes      []string
}

type PendingOffsiteGeneration struct {
	SourcePointID, SourceSnapshotID, SourceManifestDigest, SourceInventoryDigest string
	GenerationID, RepositoryID, OffsiteSnapshotID, OffsiteInventoryDigest        string
	RuleDigest                                                                   string
	SessionExpiries                                                              []time.Time
	ObjectCount, ObjectBytes                                                     int64
}

// OffsiteCustody is the privileged process boundary. Implementations must run
// the exact pinned executable under the dedicated custody identity and return
// only sanitized observations.
type OffsiteCustody interface {
	RunOffsiteRestic(context.Context, OffsiteResticRequest) (OffsiteResticResult, error)
}

type OffsiteResticRequest struct {
	BinaryPath, Architecture, RepositoryURL          string
	SnapshotPath, ExpectedSnapshotID                 string
	PasswordFDPath, IAMURI, AuthorizationTokenFDPath string
	RunID, StepID, PointID, GenerationID             string
	RecoveryEpoch                                    int64
	Arguments, Environment                           []string
}

type OffsiteResticResult struct {
	RepositoryID, SnapshotID, InventoryDigest string
	ObjectCount, ObjectBytes                  int64
	IAMCalled, ChildExited                    bool
	SessionExpiries                           []time.Time
}

type CopyConfig struct {
	Custody                                               OffsiteCustody
	Endpoint                                              *OneRunEndpoint
	BinaryPath, Architecture, RepositoryURL, SnapshotPath string
	PasswordFDPath, AuthorizationTokenFDPath              string
	IAMURI                                                string
	Binding                                               adapter.SessionRequest
}
