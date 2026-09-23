package backup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/store"
)

// OffsiteRunDeclaration is the non-secret durable mapping from one immutable
// plan target to the source point and both credentials it is allowed to borrow.
type OffsiteRunDeclaration struct {
	GenerationID, SourcePointID, SnapshotPath, RepositoryURL                          string
	ParentReferenceID, RepositoryKeyReferenceID, ObserverReferenceID                  string
	RuleDigest, G008EvidenceDigest                                                    string
	MaximumBytes, MaximumPUTs, MaximumLISTs                                           int64
	MaximumRetainedGenerations, RuleLimit                                             int
	RetentionSeconds, SessionTTLSeconds, SourceRevision, StateRevision, RecoveryEpoch int64
}

type QualifiedOffsiteRuntime interface {
	OffsitePolicy(OffsiteRunDeclaration) (OffsitePolicy, error)
	PrepareOffsiteRun(context.Context, OffsiteRunDeclaration, adapter.Operation, adapter.ExactExecutionBinding, []*credentialref.Value) (OffsiteRunSpec, error)
}

type SQLRunSpecSource struct {
	repository *store.OffsiteRepository
	runtime    QualifiedOffsiteRuntime
	endpoint   string
	bucket     string
	prefix     string
	parent     string
	observer   string
	rule       string
	evidence   string
}

func NewSQLRunSpecSource(authority *store.Store, runtime QualifiedOffsiteRuntime, endpoint, bucket, prefix, parent, observer, ruleDigest, evidenceDigest string) (*SQLRunSpecSource, error) {
	if authority == nil || runtime == nil || endpoint == "" || bucket == "" || prefix == "" || parent == "" || observer == "" || parent == observer || !validBackupManifestDigest(ruleDigest) || !validBackupManifestDigest(evidenceDigest) {
		return nil, errors.New("offsite run-spec source unavailable")
	}
	return &SQLRunSpecSource{repository: store.NewOffsiteRepository(authority), runtime: runtime, endpoint: endpoint, bucket: bucket, prefix: prefix, parent: parent, observer: observer, rule: ruleDigest, evidence: evidenceDigest}, nil
}

func (source *SQLRunSpecSource) ResolveOffsiteDeclaration(ctx context.Context, operation adapter.Operation, binding adapter.ExactExecutionBinding) (OffsiteRunDeclaration, OffsitePolicy, error) {
	if source == nil || source.repository == nil || source.runtime == nil || operation.TargetID == "" || len(operation.SecretReferences) != 3 {
		return OffsiteRunDeclaration{}, OffsitePolicy{}, errors.New("offsite run spec unavailable")
	}
	record, err := source.repository.RunSpec(ctx, operation.TargetID)
	if err != nil {
		return OffsiteRunDeclaration{}, OffsitePolicy{}, err
	}
	var declaration OffsiteRunDeclaration
	if json.Unmarshal(record.CanonicalJSON, &declaration) != nil {
		return OffsiteRunDeclaration{}, OffsitePolicy{}, errors.New("offsite run spec invalid")
	}
	canonical, err := json.Marshal(declaration)
	if err != nil || !bytes.Equal(canonical, record.CanonicalJSON) || !sameOffsiteRunSpecRecord(declaration, record) ||
		declaration.GenerationID != operation.TargetID || declaration.StateRevision != binding.StateRevision || declaration.RecoveryEpoch != binding.RecoveryEpoch ||
		declaration.ParentReferenceID != source.parent || declaration.ObserverReferenceID != source.observer || declaration.RuleDigest != source.rule || declaration.G008EvidenceDigest != source.evidence ||
		operation.SecretReferences[0].ID != declaration.ParentReferenceID || operation.SecretReferences[1].ID != declaration.RepositoryKeyReferenceID || operation.SecretReferences[2].ID != declaration.ObserverReferenceID ||
		!exactOffsiteRepositoryBinding(declaration.RepositoryURL, source.endpoint, source.bucket, source.prefix, declaration.GenerationID) {
		return OffsiteRunDeclaration{}, OffsitePolicy{}, errors.New("offsite run spec binding mismatch")
	}
	policy, err := source.runtime.OffsitePolicy(declaration)
	if err != nil {
		return OffsiteRunDeclaration{}, OffsitePolicy{}, err
	}
	return declaration, policy, nil
}

func (source *SQLRunSpecSource) PrepareOffsiteRun(ctx context.Context, declaration OffsiteRunDeclaration, operation adapter.Operation, binding adapter.ExactExecutionBinding, values []*credentialref.Value) (OffsiteRunSpec, error) {
	if source == nil || source.runtime == nil || len(values) != 3 {
		return OffsiteRunSpec{}, errors.New("offsite run spec unavailable")
	}
	return source.runtime.PrepareOffsiteRun(ctx, declaration, operation, binding, values)
}

func exactOffsiteRepositoryBinding(repositoryURL, endpoint, bucket, prefix, generationID string) bool {
	base, baseErr := url.Parse(endpoint)
	repository, repositoryErr := url.Parse(strings.TrimPrefix(repositoryURL, "s3:"))
	if baseErr != nil || repositoryErr != nil || !strings.HasPrefix(repositoryURL, "s3:") || base.Scheme != "https" || repository.Scheme != base.Scheme ||
		base.Host == "" || repository.Host != base.Host || base.User != nil || repository.User != nil || base.RawQuery != "" || repository.RawQuery != "" ||
		base.Fragment != "" || repository.Fragment != "" || base.RawPath != "" || repository.RawPath != "" || (base.Path != "" && base.Path != "/") ||
		bucket == "" || strings.Contains(bucket, "/") || prefix == "" || generationID == "" {
		return false
	}
	want := "/" + path.Join(bucket, strings.Trim(prefix, "/"), generationID)
	return repository.Path == want
}

func sameOffsiteRunSpecRecord(value OffsiteRunDeclaration, record store.OffsiteRunSpecRecord) bool {
	return value.GenerationID == record.GenerationID && value.SourcePointID == record.SourcePointID && value.SnapshotPath == record.SnapshotPath && value.RepositoryURL == record.RepositoryURL &&
		value.ParentReferenceID == record.ParentReferenceID && value.RepositoryKeyReferenceID == record.RepositoryKeyReferenceID && value.ObserverReferenceID == record.ObserverReferenceID && value.RuleDigest == record.RuleDigest && value.G008EvidenceDigest == record.G008EvidenceDigest &&
		value.MaximumBytes == record.MaximumBytes && value.MaximumPUTs == record.MaximumPUTs && value.MaximumLISTs == record.MaximumLISTs && value.MaximumRetainedGenerations == record.MaximumRetainedGenerations && value.RuleLimit == record.RuleLimit &&
		value.RetentionSeconds == record.RetentionSeconds && value.SessionTTLSeconds == record.SessionTTLSeconds && value.SourceRevision == record.SourceRevision && value.StateRevision == record.StateRevision && value.RecoveryEpoch == record.RecoveryEpoch &&
		value.RetentionSeconds <= int64((365*24*time.Hour)/time.Second) && value.SessionTTLSeconds <= int64((15*time.Minute)/time.Second)
}

var _ OffsiteRunSpecSource = (*SQLRunSpecSource)(nil)
