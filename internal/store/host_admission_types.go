package store

import "github.com/vegastack/vegastack-labs/internal/generated"

// HostAdmissionSnapshot is resolved from one authoritative read transaction.
// Fields describe provenance, never a caller-set admission decision.
type HostAdmissionSnapshot struct {
	Host                                         generated.ManagedHost
	Profile                                      generated.HostProfile
	ProfileLock                                  generated.DebianProfileLock
	RoleBindingDigest                            string
	ProfileLockDigest                            string
	IdentityDigest, BindingDigest, DeclarationID string
	DeclarationRevision                          int64
	Revision                                     RevisionToken
	Results                                      []generated.HostControlResult
	Measurements                                 []HostAdmissionMeasurement
	Evidence                                     []generated.GateEvidence
	Bundles                                      map[string]generated.GateEvidenceBundle
	AppliedBindings                              map[string]HostAppliedBinding
	ActionReceiptDigests, QualificationDigests   []string
	Qualifications                               []HostNativeQualification
	PrerequisiteDigests                          map[string]string
	PrerequisiteEvidenceIDs                      map[string]string
	NetworkingRequired, StandbyRequired          bool
	VolumeIDs                                    []string
	Storage                                      HostStoragePrerequisites
	Blockers                                     []string
}

type HostAdmissionMeasurement struct {
	Control     generated.HostControlResult
	Measurement generated.AccessMeasurement
	Result      generated.HostActionResult
	Plan        generated.Plan
	Receipt     generated.ExecutionReceipt
}

type HostAppliedBinding struct {
	ReleaseBuildID, ToolVersion                       string
	DeclarationID, ArtifactDigest, BundleDigest       string
	DeclarationRevision, StateRevision, RecoveryEpoch int64
}

// HostNativeQualification is populated only by validated internally-produced
// applied evidence. Public report JSON or measurement fields cannot create it.
type HostNativeQualification struct {
	Stage, ProfileDigest, EvidenceID, SourceDigest, ObservedAt, ExpiresAt string
	RecoveryEpoch                                                         int64
}

// HostAdmissionProvenance is installed only by trusted in-process producers.
// A verifier receives already joined applied evidence and its exact bundle.
// The v1 native producer in #228 supplies qualification; no HTTP request can
// install this interface. Nil registration leaves all native proof unavailable.
type HostAdmissionProvenance interface {
	VerifyHostEvidence(HostAdmissionSnapshot, generated.GateEvidence, generated.GateEvidenceBundle) (HostEvidenceProvenance, error)
}
type HostEvidenceProvenance struct {
	Qualification      *HostNativeQualification
	PrerequisiteID     string
	PrerequisiteDigest string
}

func NewGateRepositoryWithHostProvenance(authority *Store, verifier HostAdmissionProvenance) *GateRepository {
	return &GateRepository{store: authority, hostProvenance: verifier}
}
