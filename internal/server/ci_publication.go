package server

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/adapter/githubci"
	"github.com/vegastack/vegastack-labs/internal/ci"
	"github.com/vegastack/vegastack-labs/internal/strictjson"
	"io"
	"slices"
	"strconv"
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

// The whole candidate, including signature identity/trust policy and expected
// builder parameters, is protected installation input. Nothing signs here.
type ciPublicationCandidate struct {
	Evidence release.BuildEvidenceRequest
	Blobs    []ciPublicationBlob
}
type ciPublicationBlob struct {
	Digest string
	Size   int64
	Path   string
}
type ciPublicationFileReader func(context.Context, string, uint32, int64) ([]byte, error)
type ciPublicationAuthority interface {
	Draft(context.Context, generated.CiPublicationDraftRequest) (generated.DeclarationRevisionRequest, []credentialref.StepBinding, error)
	Snapshot(context.Context, string, int64) (store.CIPublicationExecution, error)
	Current(context.Context, adapter.Operation, adapter.ExactExecutionBinding) (store.CIPublicationExecution, error)
	Journal(context.Context, adapter.Operation, adapter.ExactExecutionBinding, string, string) error
	CheckPlan(context.Context, generated.Plan) error
	ActivePlan(context.Context, generated.Plan) (store.CIPublicationExecution, adapter.ExactExecutionBinding, error)
}
type ciPublicationEffect struct {
	binding adapter.ExactExecutionBinding
	effect  adapter.Effect
	receipt ociregistry.VerifiedPublishReceipt
	digest  string
}
type ciPublicationComposition struct {
	authority *store.Store
	registry  *adapter.Registry
	provider  *githubci.Client
	repo      ciPublicationAuthority
	owner     uint32
	read      ciPublicationFileReader
	newClient func(string) (*ociregistry.Client, error)
	mu        sync.Mutex
	results   map[string]ciPublicationEffect
}

func newCIPublicationComposition(s *store.Store, owner uint32) *ciPublicationComposition {
	provider, _ := githubci.NewClient("https://api.github.com", nil)
	return &ciPublicationComposition{authority: s, provider: provider, repo: store.NewCIPublicationRepository(s), owner: owner, read: readLocalSetupProtected, newClient: func(origin string) (*ociregistry.Client, error) { return ociregistry.NewClient(origin, nil) }, results: map[string]ciPublicationEffect{}}
}
func (c *ciPublicationComposition) candidate(ctx context.Context, x store.CIPublicationExecution) (ociregistry.VerifiedPublishRequest, error) {
	fail := func() (ociregistry.VerifiedPublishRequest, error) {
		return ociregistry.VerifiedPublishRequest{}, serviceFailure(generated.ErrorCodeEvidenceInvalid)
	}
	if c == nil || c.read == nil {
		return fail()
	}
	raw, e := c.read(ctx, x.Binding.CandidatePath, c.owner, 16<<20)
	if e != nil || hostaction.BytesDigest(raw) != x.Binding.CandidateDigest {
		return fail()
	}
	var v ciPublicationCandidate
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if strictjson.Scan(ctx, raw, strictjson.Limits{MaxDepth: 32}) != nil || d.Decode(&v) != nil || d.Decode(new(any)) != io.EOF || len(v.Blobs) < 1 || len(v.Blobs) > 16 {
		return fail()
	}
	expect := v.Evidence.Expected
	expectedInvocation := "https://github.com/" + x.Source.Repository + "/actions/runs/" + x.Source.RunID + "/attempts/" + strconv.FormatInt(x.Source.Attempt, 10) + "/jobs/" + x.Source.JobID
	if expect.SourceURI != "https://github.com/"+x.Source.Repository || expect.SourceRevision != x.Source.Revision || expect.InvocationID != expectedInvocation {
		return fail()
	}
	// Verify exact supplied Sigstore identities/provenance/SBOM before opening a
	// registry client or borrowing its credential. Unsigned producer output fails.
	if _, e = release.VerifyBuildEvidenceBytes(ctx, v.Evidence); e != nil {
		return ociregistry.VerifiedPublishRequest{}, e
	}
	q := ociregistry.VerifiedPublishRequest{Evidence: v.Evidence, Publication: ociregistry.PublishRequest{Repository: x.Binding.Repository, Digest: expect.ImageDigest, Manifest: bytes.Clone(v.Evidence.Manifest)}}
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
		q.Publication.Blobs = append(q.Publication.Blobs, ociregistry.Blob{Digest: b.Digest, Size: b.Size, Open: func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(frozen)), nil }})
	}
	return q, nil
}
func (c *ciPublicationComposition) Prepare(ctx context.Context, in generated.CiPublicationDraftRequest) (generated.DeclarationRevisionRequest, []credentialref.StepBinding, error) {
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
func (c *ciPublicationComposition) Execute(context.Context, adapter.Operation) (adapter.Effect, error) {
	return adapter.Effect{}, serviceFailure(generated.ErrorCodePrerequisiteBlocked)
}
func (c *ciPublicationComposition) ExecuteBoundWithCredentials(ctx context.Context, op adapter.Operation, b adapter.ExactExecutionBinding, values []*credentialref.Value) (adapter.Effect, error) {
	denied := func() (adapter.Effect, error) {
		return adapter.Effect{}, serviceFailure(generated.ErrorCodeAuthorizationDenied)
	}
	if c == nil || c.repo == nil || len(values) != 1 || values[0] == nil || len(values[0].Bytes()) == 0 || len(op.SecretReferences) != 1 || op.SecretReferences[0].Consumer != store.CIPublicationAdapter {
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
	q.Publication.Check = func() error { _, e := c.repo.Current(ctx, op, b); return e }
	client, e := c.newClient(x.Binding.RegistryOrigin)
	if e != nil {
		return adapter.Effect{}, e
	}
	if e = c.repo.Journal(ctx, op, b, "attempted", op.ArtifactDigest); e != nil {
		return adapter.Effect{}, e
	}
	observedSource, e := c.completed(ctx, x, op, b)
	if e != nil {
		return adapter.Effect{}, e
	}
	receipt, e := client.PublishVerified(ctx, q, values[0])
	digest := hostaction.Digest(struct {
		Publication ociregistry.VerifiedPublishReceipt
		Completed   ci.Observation
	}{receipt, observedSource})
	observed := receipt.Publication.Stage != "" && receipt.Publication.Stage != "validated"
	effect := adapter.Effect{Status: "partial", ResultDigest: digest, EffectObserved: observed, Changed: observed}
	if e != nil {
		stage := receipt.Publication.Stage
		if stage == "" {
			stage = "unstarted"
		}
		if recordErr := c.repo.Journal(context.WithoutCancel(ctx), op, b, "uncertain-"+strings.ReplaceAll(stage, "_", "-"), digest); recordErr != nil {
			return effect, serviceFailure(generated.ErrorCodeRecoveryRequired)
		}
		return effect, e
	}
	if !receipt.Publication.Verified || receipt.Publication.Stage != "manifest_verified" {
		return effect, serviceFailure(generated.ErrorCodeEvidenceInvalid)
	}
	if e = c.repo.Journal(ctx, op, b, "received", digest); e != nil {
		return effect, e
	}
	effect.Status = "succeeded"
	c.mu.Lock()
	c.results[ciPublicationVerificationKey(op, effect.ResultDigest)] = ciPublicationEffect{b, effect, receipt, digest}
	c.mu.Unlock()
	return effect, nil
}
func (c *ciPublicationComposition) Verify(_ context.Context, op adapter.Operation, effect adapter.Effect) (adapter.Verification, error) {
	if c == nil {
		return adapter.Verification{}, serviceFailure(generated.ErrorCodeAuthorizationDenied)
	}
	c.mu.Lock()
	record, ok := c.results[ciPublicationVerificationKey(op, effect.ResultDigest)]
	delete(c.results, ciPublicationVerificationKey(op, effect.ResultDigest))
	c.mu.Unlock()
	if !ok || record.effect != effect || effect.Status != "succeeded" || !record.receipt.Publication.Verified || record.digest != effect.ResultDigest {
		return adapter.Verification{}, serviceFailure(generated.ErrorCodeEvidenceInvalid)
	}
	return adapter.Verification{Verified: true, Digest: effect.ResultDigest}, nil
}

type ciPublicationGate struct {
	source   *ciPublicationComposition
	fallback run.GateVerifier
}

func (g ciPublicationGate) VerifySecretStep(ctx context.Context, p generated.Plan, op generated.PlanOperation) error {
	if op.OperationType == store.CIPublicationOperation || op.AdapterID == store.CIPublicationAdapter {
		if g.source == nil || len(p.Operations) != 1 || p.Operations[0] != op {
			return serviceFailure(generated.ErrorCodeAuthorizationDenied)
		}
		x, b, e := g.source.repo.ActivePlan(ctx, p)
		if e != nil {
			return e
		}
		op := p.Operations[0]
		_, e = g.source.completed(ctx, x, adapter.Operation{OperationID: op.OperationID, OperationType: op.OperationType, AdapterID: op.AdapterID, ExecutorID: op.ExecutorID, TargetID: op.TargetID, InputDigest: op.InputDigest, ArtifactDigest: op.ArtifactDigest, Idempotent: op.Idempotent}, b)
		return e
	}
	if g.fallback == nil {
		return serviceFailure(generated.ErrorCodePrerequisiteBlocked)
	}
	return g.fallback.VerifySecretStep(ctx, p, op)
}

// Reuse only the source job's protected, currently activated observation
// reference. The read credential never becomes publication or hosting material.
func (c *ciPublicationComposition) completed(ctx context.Context, x store.CIPublicationExecution, op adapter.Operation, b adapter.ExactExecutionBinding) (ci.Observation, error) {
	empty := ci.Observation{}
	if c.authority == nil || c.registry == nil || c.provider == nil {
		return empty, serviceFailure(generated.ErrorCodePrerequisiteBlocked)
	}
	observer := x.Source.Observer
	observer.StateRevision = b.StateRevision
	observer.RecoveryEpoch = b.RecoveryEpoch
	refs := store.NewCredentialRepository(c.authority)
	gates := store.NewGateRepository(c.authority)
	reference, e := refs.GetActiveVersion(ctx, observer.ReferenceID, b.RecoveryEpoch)
	if e != nil {
		return empty, e
	}
	validate := func() error {
		if _, e := c.repo.Current(ctx, op, b); e != nil {
			return e
		}
		profile, e := gates.GetAppliedProfileScope(ctx)
		if e != nil || profile.RecoveryEpoch != b.RecoveryEpoch || profile.StateRevision > b.StateRevision || !slices.Contains(profile.Capabilities, "credential.host-action.read") {
			return serviceFailure(generated.ErrorCodePrerequisiteBlocked)
		}
		current, e := refs.GetActiveVersion(ctx, observer.ReferenceID, b.RecoveryEpoch)
		if e != nil || hostaction.Digest(current) != hostaction.Digest(reference) {
			return serviceFailure(generated.ErrorCodePlanStale)
		}
		if current.ConsumerID != observer.ConsumerID || current.PurposeID != observer.PurposeID || current.TargetID != observer.TargetID || current.MaterialVersion != observer.MaterialVersion || current.Status != "active" || current.ActivatedAt == nil || current.StateRevision > b.StateRevision || current.ResolverID != observer.ResolverID || !slices.Contains(current.VerifiedConsumerIDs, observer.ConsumerID) {
			return serviceFailure(generated.ErrorCodePrerequisiteBlocked)
		}
		capability, e := c.registry.ResolveCredentialCapability(observer.ResolverID, observer.ConsumerID, profile.ProfileID)
		if e != nil || capability != "credential.host-action.read" {
			return serviceFailure(generated.ErrorCodePrerequisiteBlocked)
		}
		return nil
	}
	if e = validate(); e != nil {
		return empty, e
	}
	profile, e := gates.GetAppliedProfileScope(ctx)
	if e != nil {
		return empty, e
	}
	resolver, e := c.registry.ResolveCredentialResolver(observer.ResolverID, observer.ConsumerID, profile.ProfileID)
	if e != nil {
		return empty, e
	}
	value, e := resolver.Resolve(ctx, observer)
	if e != nil {
		if value != nil {
			value.Close()
		}
		return empty, serviceFailure(generated.ErrorCodePrerequisiteBlocked)
	}
	if value == nil {
		return empty, serviceFailure(generated.ErrorCodePrerequisiteBlocked)
	}
	defer value.Close()
	p := x.Source.Policy
	target := githubci.Target{Enrollment: ci.Enrollment{ID: x.Source.Definition.EnrollmentID, Binding: ci.Binding{RepositoryID: p.RepositoryID, OwnerID: p.OwnerID, Repository: p.Repository, WorkflowID: p.WorkflowID, WorkflowPath: p.WorkflowPath, WorkflowDigest: p.WorkflowDigest, Revision: p.Revision, Ref: p.Ref, Event: p.Event, JobName: p.JobName, RunnerID: x.Source.RunnerID, RunnerGroupID: p.RunnerGroupID, Labels: slices.Clone(p.Labels)}}, RunID: x.Source.RunID, JobID: x.Source.JobID, Attempt: uint32(x.Source.Attempt)}
	return c.provider.ObserveCompletedSuccess(ctx, githubci.CompletedTarget{Target: target, GroupName: x.Source.GroupName, Check: validate}, value)
}

// JIT references exist only at Execute; InputDigest already seals their exact
// manifest. Verify receives the original public operation after values close.
func ciPublicationVerificationKey(op adapter.Operation, digest string) string {
	op.SecretReferences = nil
	return hostaction.Digest(op) + "/" + digest
}
