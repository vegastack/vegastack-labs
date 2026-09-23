package backup

import (
	"context"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
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
	ProtectedRules                          []adapter.RetentionRule
	MutablePrefixes                         []string
}

// OffsiteObject is one exact provider-observed object. Key is relative to the
// generation prefix and Digest binds the stored bytes, never provider prose.
type OffsiteObject struct {
	Key    string
	Digest string
	Bytes  int64
}

type PendingOffsiteGeneration struct {
	SourcePointID, SourceSnapshotID, SourceManifestDigest, SourceInventoryDigest    string
	SourceContentDigest, SourceDependencyDigest, SourceResticDigest, KeyReferenceID string
	GenerationID, RepositoryID, OffsiteSnapshotID, OffsiteInventoryDigest           string
	RuleDigest                                                                      string
	ProtectedRules                                                                  []adapter.RetentionRule
	Objects                                                                         []OffsiteObject
	SessionExpiries                                                                 []time.Time
	SourceRevision, StateRevision, RecoveryEpoch, ObjectCount, ObjectBytes          int64
	IssuanceStoppedAt                                                               time.Time
}

// OffsiteCustody is the privileged process boundary. Implementations must run
// the exact pinned executable under the dedicated custody identity and return
// only sanitized observations.
type OffsiteCustody interface {
	RunOffsiteRestic(context.Context, OffsiteResticRequest, *credentialref.Value, []byte) (OffsiteResticResult, error)
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
	RepositoryID, SnapshotID string
	ObjectCount, ObjectBytes int64
	ChildExited              bool
	FullReadAt               time.Time
}

type OffsiteInventoryObservation struct {
	InventoryDigest          string
	ObjectCount, ObjectBytes int64
	Objects                  []OffsiteObject
}

// OffsiteInventoryObserver reads the destination after the child exits. The
// custody child cannot infer an S3 object inventory from restic's backup
// summary, so the adapter must return the provider-observed generation state.
type OffsiteInventoryObserver interface {
	ObserveOffsiteGeneration(context.Context, string, string, string) (OffsiteInventoryObservation, error)
}

type CopyConfig struct {
	Custody                                                       OffsiteCustody
	Endpoint                                                      *OneRunEndpoint
	BinaryPath, Architecture, RepositoryURL, Bucket, SnapshotPath string
	PasswordFDPath, AuthorizationTokenFDPath                      string
	IAMURI                                                        string
	Password                                                      *credentialref.Value
	Inventory                                                     OffsiteInventoryObserver
	Binding                                                       adapter.SessionRequest
}
