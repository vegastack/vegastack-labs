// Package stateexport owns deterministic, inert inventory-draft export bytes.
// It deliberately contains no signing key implementation or production trust.
package stateexport

import "github.com/vegastack/vegastack-labs/internal/inventory"

const (
	PayloadSchema        = "vegastack-labs.dev/inventory-draft-snapshot-payload"
	SignedExportSchema   = "vegastack-labs.dev/signed-inventory-draft-export"
	PointerSchema        = "vegastack-labs.dev/inventory-draft-export-pointer"
	SchemaVersion        = "1.0.0"
	ExportKind           = "inventory-draft-snapshot"
	SubjectKind          = "draft"
	VerificationVerified = "verified"
	MaxArtifactBytes     = 16 << 20
)

type KindCount struct {
	Kind  string `json:"kind"`
	Count int64  `json:"count"`
}

type Payload struct {
	Schema         string                           `json:"schema"`
	SchemaVersion  string                           `json:"schemaVersion"`
	ExportKind     string                           `json:"exportKind"`
	SubjectKind    string                           `json:"subjectKind"`
	RecoveryEpoch  int64                            `json:"recoveryEpoch"`
	StateRevision  int64                            `json:"stateRevision"`
	ToolVersion    string                           `json:"toolVersion"`
	ReleaseBuildID string                           `json:"releaseBuildId"`
	SourceRevision *string                          `json:"sourceRevision"`
	Contents       []KindCount                      `json:"contents"`
	Draft          inventory.CanonicalDraftSnapshot `json:"draft"`
}

type DetachedSignature struct {
	Algorithm      string `json:"algorithm"`
	KeyID          string `json:"keyId"`
	KeyFingerprint string `json:"keyFingerprint"`
	Value          string `json:"value"`
}

type SignedExport struct {
	Schema             string            `json:"schema"`
	SchemaVersion      string            `json:"schemaVersion"`
	Payload            Payload           `json:"payload"`
	ContentDigest      string            `json:"contentDigest"`
	Signature          DetachedSignature `json:"signature"`
	VerificationStatus string            `json:"verificationStatus"`
}

type CurrentPointer struct {
	Schema        string `json:"schema"`
	SchemaVersion string `json:"schemaVersion"`
	ExportKind    string `json:"exportKind"`
	ArtifactID    string `json:"artifactId"`
	ContentDigest string `json:"contentDigest"`
}
