package server

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/strictjson"
	"io"
	"strings"
	"sync"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/adapter/ociregistry"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/release"
	"github.com/vegastack/vegastack-labs/internal/run"
	"github.com/vegastack/vegastack-labs/internal/store"
)

// The whole candidate, with signed image bytes but no trust policy, is protected installation input. Nothing signs here.
type manualPublicationCandidate struct {
	Manifest []byte
	Bundle   []byte
	Blobs    []manualPublicationBlob
}
type manualPublicationBlob struct {
	Digest string
	Size   int64
	Path   string
}
type manualPublicationFileReader func(context.Context, string, uint32, int64) ([]byte, error)
type manualPublicationAuthority interface {
	Draft(context.Context, generated.ManualPublicationDraftRequest) (generated.DeclarationRevisionRequest, []credentialref.StepBinding, error)
	Snapshot(context.Context, string, int64) (store.ManualPublicationExecution, error)
	Current(context.Context, adapter.Operation, adapter.ExactExecutionBinding) (store.ManualPublicationExecution, error)
	Journal(context.Context, adapter.Operation, adapter.ExactExecutionBinding, string, string) error
	CheckPlan(context.Context, generated.Plan) error
	ActivePlan(context.Context, generated.Plan) (store.ManualPublicationExecution, adapter.ExactExecutionBinding, error)
}
type manualPublicationEffect struct {
	binding adapter.ExactExecutionBinding
	effect  adapter.Effect
	receipt ociregistry.PublishReceipt
	digest  string
}
type manualPublicationComposition struct {
	repo      manualPublicationAuthority
	owner     uint32
	read      manualPublicationFileReader
	newClient func(string) (*ociregistry.Client, error)
	mu        sync.Mutex
	results   map[string]manualPublicationEffect
}

func newManualPublicationComposition(s *store.Store, owner uint32) *manualPublicationComposition {
	return &manualPublicationComposition{repo: store.NewManualPublicationRepository(s), owner: owner, read: readLocalSetupProtected, newClient: func(origin string) (*ociregistry.Client, error) { return ociregistry.NewClient(origin, nil) }, results: map[string]manualPublicationEffect{}}
}
func (c *manualPublicationComposition) candidate(ctx context.Context, x store.ManualPublicationExecution) (ociregistry.PublishRequest, error) {
	fail := func() (ociregistry.PublishRequest, error) {
		return ociregistry.PublishRequest{}, serviceFailure(generated.ErrorCodeEvidenceInvalid)
	}
	if c == nil || c.read == nil {
		return fail()
	}
	raw, e := c.read(ctx, x.Binding.CandidatePath, c.owner, 16<<20)
	if e != nil || hostaction.BytesDigest(raw) != x.Binding.CandidateDigest {
		return fail()
	}
	var v manualPublicationCandidate
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if strictjson.Scan(ctx, raw, strictjson.Limits{MaxDepth: 32}) != nil || d.Decode(&v) != nil || d.Decode(new(any)) != io.EOF || len(v.Blobs) < 1 || len(v.Blobs) > 16 {
		return fail()
	}
	policy, e := c.read(ctx, x.Binding.TrustPolicyPath, c.owner, 1<<20)
	if e != nil || hostaction.BytesDigest(policy) != x.Binding.TrustPolicyDigest {
		return fail()
	}
	// Trust comes from a separately pinned file, never from artifact input.
	var trust generated.ReleaseTrustPolicy
	if generated.ValidateContractJSON(generated.SchemaIDReleaseTrustPolicy, policy, generated.ContractExact) != nil || json.Unmarshal(policy, &trust) != nil {
		return fail()
	}
	if _, e = release.VerifyOCIBytes(ctx, v.Manifest, v.Bundle, policy, x.Binding.ImageDigest); e != nil {
		return ociregistry.PublishRequest{}, e
	}
	q := ociregistry.PublishRequest{Repository: x.Binding.Repository, Digest: x.Binding.ImageDigest, Manifest: bytes.Clone(v.Manifest)}
	var total int64
	for _, b := range v.Blobs {
		if b.Size < 0 || b.Size > 64<<20 {
			return fail()
		}
		total += b.Size
		if total > 128<<20 {
			return fail()
		}
		content, e := c.read(ctx, b.Path, c.owner, b.Size+1)
		if e != nil || int64(len(content)) != b.Size || hostaction.BytesDigest(content) != b.Digest {
			return fail()
		}
		frozen := bytes.Clone(content)
		q.Blobs = append(q.Blobs, ociregistry.Blob{Digest: b.Digest, Size: b.Size, Open: func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(frozen)), nil }})
	}
	return q, nil
}
func (c *manualPublicationComposition) Prepare(ctx context.Context, in generated.ManualPublicationDraftRequest) (generated.DeclarationRevisionRequest, []credentialref.StepBinding, error) {
	d, b, e := c.repo.Draft(ctx, in)
	if e != nil {
		return d, b, e
	}
	x, e := c.repo.Snapshot(ctx, in.BindingID, in.RecoveryEpoch)
	if e != nil {
		return generated.DeclarationRevisionRequest{}, nil, e
	}
	_, e = c.candidate(ctx, x)
	if e != nil {
		return generated.DeclarationRevisionRequest{}, nil, e
	}
	return d, b, nil
}
func (c *manualPublicationComposition) Execute(context.Context, adapter.Operation) (adapter.Effect, error) {
	return adapter.Effect{}, serviceFailure(generated.ErrorCodePrerequisiteBlocked)
}
func (c *manualPublicationComposition) ExecuteBoundWithCredentials(ctx context.Context, op adapter.Operation, b adapter.ExactExecutionBinding, values []*credentialref.Value) (adapter.Effect, error) {
	denied := func() (adapter.Effect, error) {
		return adapter.Effect{}, serviceFailure(generated.ErrorCodeAuthorizationDenied)
	}
	if c == nil || c.repo == nil || len(values) != 1 || values[0] == nil || len(values[0].Bytes()) == 0 || len(op.SecretReferences) != 1 || op.SecretReferences[0].Consumer != store.ManualPublicationAdapter {
		return denied()
	}
	x, e := c.repo.Current(ctx, op, b)
	if e != nil {
		return adapter.Effect{}, e
	}
	if op.SecretReferences[0].ID != x.Binding.ReferenceID {
		return denied()
	}
	q, e := c.candidate(ctx, x)
	if e != nil {
		return adapter.Effect{}, e
	}
	q.Check = func() error { _, e := c.repo.Current(ctx, op, b); return e }
	client, e := c.newClient(x.Binding.RegistryOrigin)
	if e != nil {
		return adapter.Effect{}, e
	}
	if e = c.repo.Journal(ctx, op, b, "attempted", op.ArtifactDigest); e != nil {
		return adapter.Effect{}, e
	}
	receipt, e := client.Publish(ctx, q, values[0])
	digest := hostaction.Digest(receipt)
	observed := receipt.Stage != "" && receipt.Stage != "validated"
	effect := adapter.Effect{Status: "partial", ResultDigest: digest, EffectObserved: observed, Changed: observed}
	if e != nil {
		stage := receipt.Stage
		if stage == "" {
			stage = "unstarted"
		}
		if recordErr := c.repo.Journal(context.WithoutCancel(ctx), op, b, "uncertain-"+strings.ReplaceAll(stage, "_", "-"), digest); recordErr != nil {
			return effect, serviceFailure(generated.ErrorCodeRecoveryRequired)
		}
		return effect, e
	}
	if !receipt.Verified || receipt.Stage != "manifest_verified" {
		return effect, serviceFailure(generated.ErrorCodeEvidenceInvalid)
	}
	if e = c.repo.Journal(ctx, op, b, "received", digest); e != nil {
		return effect, e
	}
	effect.Status = "succeeded"
	c.mu.Lock()
	c.results[manualPublicationVerificationKey(op, effect.ResultDigest)] = manualPublicationEffect{b, effect, receipt, digest}
	c.mu.Unlock()
	return effect, nil
}
func (c *manualPublicationComposition) Verify(_ context.Context, op adapter.Operation, effect adapter.Effect) (adapter.Verification, error) {
	if c == nil {
		return adapter.Verification{}, serviceFailure(generated.ErrorCodeAuthorizationDenied)
	}
	c.mu.Lock()
	record, ok := c.results[manualPublicationVerificationKey(op, effect.ResultDigest)]
	delete(c.results, manualPublicationVerificationKey(op, effect.ResultDigest))
	c.mu.Unlock()
	if !ok || record.effect != effect || effect.Status != "succeeded" || !record.receipt.Verified || record.digest != effect.ResultDigest {
		return adapter.Verification{}, serviceFailure(generated.ErrorCodeEvidenceInvalid)
	}
	return adapter.Verification{Verified: true, Digest: effect.ResultDigest}, nil
}

type manualPublicationGate struct {
	source   *manualPublicationComposition
	fallback run.GateVerifier
}

func (g manualPublicationGate) VerifySecretStep(ctx context.Context, p generated.Plan, op generated.PlanOperation) error {
	if op.OperationType == store.ManualPublicationOperation || op.AdapterID == store.ManualPublicationAdapter {
		if g.source == nil || len(p.Operations) != 1 || p.Operations[0] != op {
			return serviceFailure(generated.ErrorCodeAuthorizationDenied)
		}
		x, _, e := g.source.repo.ActivePlan(ctx, p)
		if e != nil {
			return e
		}
		_, e = g.source.candidate(ctx, x)
		return e
	}
	if g.fallback == nil {
		return serviceFailure(generated.ErrorCodePrerequisiteBlocked)
	}
	return g.fallback.VerifySecretStep(ctx, p, op)
}

func manualPublicationVerificationKey(op adapter.Operation, digest string) string {
	op.SecretReferences = nil
	return hostaction.Digest(op) + "/" + digest
}
