package backup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/store"
)

// OffsiteRunDeclaration is the non-secret durable mapping from one immutable
// plan target to the source point and both credentials it is allowed to borrow.
type OffsiteRunDeclaration struct {
	GenerationID, SourcePointID, SnapshotPath, RepositoryURL               string
	ParentReferenceID, PasswordReferenceID, RuleDigest, G008EvidenceDigest string
	MaximumBytes, MaximumPUTs, MaximumLISTs                                int64
	MaximumRetainedGenerations, RuleLimit                                  int
	RetentionSeconds, SessionTTLSeconds, StateRevision, RecoveryEpoch      int64
}

type QualifiedOffsiteRuntime interface {
	PrepareOffsiteRun(context.Context, OffsiteRunDeclaration, adapter.Operation, adapter.ExactExecutionBinding, []*credentialref.Value) (OffsiteRunSpec, error)
}

type SQLRunSpecSource struct {
	repository *store.OffsiteRepository
	runtime    QualifiedOffsiteRuntime
	endpoint   string
	bucket     string
	prefix     string
	parent     string
	rule       string
	evidence   string
}

func NewSQLRunSpecSource(authority *store.Store, runtime QualifiedOffsiteRuntime, endpoint, bucket, prefix, parent, ruleDigest, evidenceDigest string) (*SQLRunSpecSource, error) {
	if authority == nil || runtime == nil || endpoint == "" || bucket == "" || prefix == "" || parent == "" || !validBackupManifestDigest(ruleDigest) || !validBackupManifestDigest(evidenceDigest) {
		return nil, errors.New("offsite run-spec source unavailable")
	}
	return &SQLRunSpecSource{repository: store.NewOffsiteRepository(authority), runtime: runtime, endpoint: endpoint, bucket: bucket, prefix: prefix, parent: parent, rule: ruleDigest, evidence: evidenceDigest}, nil
}

func (source *SQLRunSpecSource) ResolveOffsiteRun(ctx context.Context, operation adapter.Operation, binding adapter.ExactExecutionBinding, values []*credentialref.Value) (OffsiteRunSpec, error) {
	if source == nil || source.repository == nil || source.runtime == nil || operation.TargetID == "" || len(operation.SecretReferences) != 2 || len(values) != 2 {
		return OffsiteRunSpec{}, errors.New("offsite run spec unavailable")
	}
	record, err := source.repository.RunSpec(ctx, operation.TargetID)
	if err != nil {
		return OffsiteRunSpec{}, err
	}
	var declaration OffsiteRunDeclaration
	if json.Unmarshal(record.CanonicalJSON, &declaration) != nil {
		return OffsiteRunSpec{}, errors.New("offsite run spec invalid")
	}
	canonical, err := json.Marshal(declaration)
	if err != nil || !bytes.Equal(canonical, record.CanonicalJSON) || !sameOffsiteRunSpecRecord(declaration, record) ||
		declaration.GenerationID != operation.TargetID || declaration.StateRevision != binding.StateRevision || declaration.RecoveryEpoch != binding.RecoveryEpoch ||
		declaration.ParentReferenceID != source.parent || declaration.RuleDigest != source.rule || declaration.G008EvidenceDigest != source.evidence ||
		operation.SecretReferences[0].ID != declaration.ParentReferenceID || operation.SecretReferences[1].ID != declaration.PasswordReferenceID ||
		!strings.Contains(declaration.RepositoryURL, "://"+strings.TrimPrefix(source.endpoint, "https://")) || !strings.Contains(declaration.RepositoryURL, "/"+source.bucket+"/"+strings.Trim(source.prefix, "/")+"/") {
		return OffsiteRunSpec{}, errors.New("offsite run spec binding mismatch")
	}
	return source.runtime.PrepareOffsiteRun(ctx, declaration, operation, binding, values)
}

func sameOffsiteRunSpecRecord(value OffsiteRunDeclaration, record store.OffsiteRunSpecRecord) bool {
	return value.GenerationID == record.GenerationID && value.SourcePointID == record.SourcePointID && value.SnapshotPath == record.SnapshotPath && value.RepositoryURL == record.RepositoryURL &&
		value.ParentReferenceID == record.ParentReferenceID && value.PasswordReferenceID == record.PasswordReferenceID && value.RuleDigest == record.RuleDigest && value.G008EvidenceDigest == record.G008EvidenceDigest &&
		value.MaximumBytes == record.MaximumBytes && value.MaximumPUTs == record.MaximumPUTs && value.MaximumLISTs == record.MaximumLISTs && value.MaximumRetainedGenerations == record.MaximumRetainedGenerations && value.RuleLimit == record.RuleLimit &&
		value.RetentionSeconds == record.RetentionSeconds && value.SessionTTLSeconds == record.SessionTTLSeconds && value.StateRevision == record.StateRevision && value.RecoveryEpoch == record.RecoveryEpoch &&
		value.RetentionSeconds <= int64((365*24*time.Hour)/time.Second) && value.SessionTTLSeconds <= int64((15*time.Minute)/time.Second)
}

var _ OffsiteRunSpecSource = (*SQLRunSpecSource)(nil)
