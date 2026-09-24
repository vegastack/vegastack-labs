//go:build linux

package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/adapter/r2retention"
	"github.com/vegastack/vegastack-labs/internal/adapters/r2"
	"github.com/vegastack/vegastack-labs/internal/api"
	"github.com/vegastack/vegastack-labs/internal/backup"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	runengine "github.com/vegastack/vegastack-labs/internal/run"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type labsR2RetirementProviders struct {
	profile   *serverconfig.OffsiteBackup
	local     *serverconfig.LocalBackup
	authority *store.Store
	inspector store.RestoredSQLiteInspector
}

func (providers labsR2RetirementProviders) Clients(_ context.Context, intent store.OffsiteRetirementIntent, binding adapter.ExactExecutionBinding, lockAdmin, retention *credentialref.Value, repositoryKeys map[string]*credentialref.Value) (r2retention.RuleClient, r2retention.ObjectClient, backup.OffsiteSurvivorVerifier, error) {
	if providers.profile == nil || lockAdmin == nil || retention == nil || intent.BucketID != providers.profile.Bucket || intent.GenerationID == "" ||
		intent.LockAdminReferenceID != providers.profile.LockAdminReferenceID || intent.LockAdminFingerprint != providers.profile.LockAdminFingerprint || intent.RetentionReferenceID != providers.profile.RetentionReferenceID || intent.RetentionFingerprint != providers.profile.RetentionFingerprint {
		return nil, nil, nil, errors.New("r2 retirement provider binding unavailable")
	}
	credentials, err := r2.ParseParentS3Credentials(retention.Bytes())
	if err != nil {
		return nil, nil, nil, err
	}
	rules := &boundR2Rules{client: r2.RetentionClient{AccountID: providers.profile.AccountID, Bucket: providers.profile.Bucket, Clock: time.Now}, bearer: append([]byte(nil), lockAdmin.Bytes()...)}
	objects := &boundR2Objects{client: r2.S3Client{Endpoint: providers.profile.Endpoint, Bucket: providers.profile.Bucket, Clock: time.Now}, credentials: credentials, prefix: strings.TrimSuffix(providers.profile.Prefix, "/") + "/" + intent.GenerationID}
	verifierCredentials := r2.S3Credentials{AccessKeyID: append([]byte(nil), credentials.AccessKeyID...), SecretAccessKey: append([]byte(nil), credentials.SecretAccessKey...), SessionToken: append([]byte(nil), credentials.SessionToken...)}
	keyCopies := map[string]*credentialref.Value{}
	for referenceID, value := range repositoryKeys {
		copied, copyErr := credentialref.NewValue(value.Bytes())
		if copyErr != nil {
			rules.Close()
			objects.Close()
			for _, prior := range keyCopies {
				prior.Close()
			}
			return nil, nil, nil, copyErr
		}
		keyCopies[referenceID] = copied
	}
	parentCopy, copyErr := credentialref.NewValue(retention.Bytes())
	if copyErr != nil {
		rules.Close()
		objects.Close()
		for _, prior := range keyCopies {
			prior.Close()
		}
		return nil, nil, nil, copyErr
	}
	verifier := &labsR2SurvivorVerifier{authority: providers.authority, profile: providers.profile, local: providers.local, inspector: providers.inspector, intent: intent, binding: binding, repository: store.NewOffsiteRetirementRepository(providers.authority), client: r2.S3Client{Endpoint: providers.profile.Endpoint, Bucket: providers.profile.Bucket, Clock: time.Now}, credentials: verifierCredentials, parent: parentCopy, repositoryKeys: keyCopies, prefix: strings.TrimSuffix(providers.profile.Prefix, "/"), clock: time.Now}
	return rules, objects, verifier, nil
}

type labsR2SurvivorVerifier struct {
	authority      *store.Store
	profile        *serverconfig.OffsiteBackup
	local          *serverconfig.LocalBackup
	inspector      store.RestoredSQLiteInspector
	intent         store.OffsiteRetirementIntent
	binding        adapter.ExactExecutionBinding
	repository     *store.OffsiteRetirementRepository
	client         r2.S3Client
	credentials    r2.S3Credentials
	parent         *credentialref.Value
	repositoryKeys map[string]*credentialref.Value
	prefix         string
	clock          func() time.Time
}

func (verifier *labsR2SurvivorVerifier) VerifyOffsiteSurvivor(ctx context.Context, pointID string) (backup.OffsiteSurvivorProof, error) {
	if verifier == nil || verifier.repository == nil || verifier.clock == nil {
		return backup.OffsiteSurvivorProof{}, errors.New("fresh survivor verifier unavailable")
	}
	expected, err := verifier.repository.ExpectedOffsiteSurvivor(ctx, pointID)
	if err != nil {
		return backup.OffsiteSurvivorProof{}, err
	}
	observed, err := verifier.client.Inventory(ctx, verifier.prefix+"/"+expected.GenerationID, verifier.credentials, 1_000_000, 1<<50)
	if err != nil || observed.InventoryDigest != expected.InventoryDigest {
		return backup.OffsiteSurvivorProof{}, errors.New("fresh survivor full read failed")
	}
	var referenceID string
	for _, key := range verifier.intent.SurvivorKeyReferences {
		if key.PointID == pointID {
			referenceID = key.ReferenceID
		}
	}
	password := verifier.repositoryKeys[referenceID]
	if verifier.local == nil || password == nil {
		return backup.OffsiteSurvivorProof{}, errors.New("fresh survivor restore binding unavailable")
	}
	proof, err := r2.VerifyRetirementSurvivor(ctx, r2.RetirementSurvivorVerificationConfig{Authority: verifier.authority, Intent: verifier.intent, Binding: verifier.binding, Endpoint: verifier.profile.Endpoint, Bucket: verifier.profile.Bucket, Prefix: verifier.prefix, ParentReferenceID: verifier.profile.ParentReferenceID, ParentFingerprint: verifier.profile.ParentFingerprint, ResticBinaryPath: verifier.local.ResticBinaryPath, CustodyPolicyPath: verifier.local.CustodyPolicyPath, Parent: verifier.parent, RepositoryKey: password, Inspector: verifier.inspector, Clock: verifier.clock}, pointID)
	if err != nil {
		return backup.OffsiteSurvivorProof{}, err
	}
	proof.InventoryDigest = observed.InventoryDigest
	return proof, nil
}

func (verifier *labsR2SurvivorVerifier) Close() error {
	if verifier != nil {
		zeroCredential(verifier.credentials.AccessKeyID)
		zeroCredential(verifier.credentials.SecretAccessKey)
		zeroCredential(verifier.credentials.SessionToken)
		verifier.credentials = r2.S3Credentials{}
		if verifier.parent != nil {
			verifier.parent.Close()
			verifier.parent = nil
		}
		for id, value := range verifier.repositoryKeys {
			if value != nil {
				value.Close()
			}
			delete(verifier.repositoryKeys, id)
		}
	}
	return nil
}

type r2RetirementCredentialResolver struct {
	profile     *serverconfig.OffsiteBackup
	systemd     *systemdCredentialResolver
	retirements *store.OffsiteRetirementRepository
}

func (resolver *r2RetirementCredentialResolver) Resolve(ctx context.Context, binding credentialref.StepBinding) (*credentialref.Value, error) {
	if resolver == nil || resolver.profile == nil || resolver.systemd == nil || binding.ConsumerID != "r2.retention" || binding.ResolverID != "native-systemd" || binding.AdapterID != "r2.retention" {
		return nil, errors.New("r2 retirement credential binding unavailable")
	}
	qualifiedKey := false
	if binding.PurposeID == "repository-key" && resolver.retirements != nil {
		qualifiedKey, _ = resolver.retirements.IsQualifiedSurvivorKey(ctx, binding.ReferenceID, binding.RecoveryEpoch)
	}
	if (binding.PurposeID == "lock-admin" && binding.ReferenceID != resolver.profile.LockAdminReferenceID) || (binding.PurposeID == "retention" && binding.ReferenceID != resolver.profile.RetentionReferenceID) || (binding.PurposeID == "repository-key" && !qualifiedKey) || (binding.PurposeID != "lock-admin" && binding.PurposeID != "retention" && binding.PurposeID != "repository-key") {
		return nil, errors.New("r2 retirement credential binding invalid")
	}
	raw, err := resolver.systemd.Resolve(ctx, credentialref.Reference{ID: binding.ReferenceID, Consumer: binding.ConsumerID})
	if err != nil {
		return nil, err
	}
	defer zeroCredential(raw)
	expectedFingerprint := ""
	if binding.PurposeID == "lock-admin" {
		expectedFingerprint = resolver.profile.LockAdminFingerprint
	} else if binding.PurposeID == "retention" {
		expectedFingerprint = resolver.profile.RetentionFingerprint
	}
	if expectedFingerprint != "" {
		sum := sha256.Sum256(raw)
		if "sha256:"+hex.EncodeToString(sum[:]) != expectedFingerprint {
			return nil, errors.New("r2 retirement credential fingerprint mismatch")
		}
	}
	return credentialref.NewValue(raw)
}

type r2RetirementLiveGate struct {
	gates       *store.GateRepository
	retirements *store.OffsiteRetirementRepository
	clock       func() time.Time
}

func (gate r2RetirementLiveGate) VerifySecretStep(ctx context.Context, plan generated.Plan, operation generated.PlanOperation) error {
	if gate.gates == nil || gate.retirements == nil || operation.OperationType != "backup.retire.offsite" || operation.AdapterID != "r2.retention" || operation.ArtifactDigest == "" {
		return errors.New("r2 retirement live gate unavailable")
	}
	intent, err := gate.retirements.GetOffsiteRetirementIntentByDigest(ctx, operation.ArtifactDigest)
	if err != nil || intent.PlanID != plan.PlanID || intent.PlanDigest != plan.PlanDigest || intent.GenerationID != operation.TargetID || intent.StateRevision != plan.Binding.StateRevision || intent.RecoveryEpoch != plan.Binding.RecoveryEpoch {
		return errors.New("r2 retirement live gate binding invalid")
	}
	_, err = gate.gates.ResolveCurrentLiveGateEvidenceWithExclusiveAdmin(ctx, "G-008", intent.G008BundleDigest, intent.QualificationDigest, intent.PutCutoffDigest, intent.MultipartCutoffDigest, intent.ExclusiveAdminDigest, gate.clock().UTC())
	return err
}

func composeR2RetirementCredentials(ctx context.Context, profile serverconfig.Profile, registry *adapter.Registry, gates *store.GateRepository, retirements *store.OffsiteRetirementRepository) (runengine.GateVerifier, error) {
	if ctx == nil || profile.OffsiteBackup == nil || registry == nil || gates == nil || retirements == nil {
		return nil, errors.New("r2 retirement credential composition unavailable")
	}
	scope, err := gates.GetAppliedProfileScope(ctx)
	if err != nil || !slices.Contains(scope.Capabilities, "credential.native.read") {
		return nil, errors.New("r2 retirement credential capability unavailable")
	}
	systemd, err := newSystemdCredentialResolver(profile.SocketOwnerUID)
	if err != nil {
		return nil, err
	}
	resolver := &r2RetirementCredentialResolver{profile: profile.OffsiteBackup, systemd: systemd, retirements: retirements}
	if err := registry.RegisterCredentialResolver(adapter.CredentialCapabilityScope{ResolverID: "native-systemd", ConsumerID: "r2.retention", ProfileID: scope.ProfileID, CapabilityID: "credential.native.read", Enabled: true}, resolver); err != nil {
		_ = systemd.directory.Close()
		return nil, err
	}
	return r2RetirementLiveGate{gates: gates, retirements: retirements, clock: time.Now}, nil
}

type boundR2Rules struct {
	client r2.RetentionClient
	bearer []byte
}

func (client *boundR2Rules) ReadRules(ctx context.Context, bucket string) (r2retention.RuleSet, error) {
	return client.client.ReadRulesWithBearer(ctx, bucket, client.bearer)
}
func (client *boundR2Rules) PutRules(ctx context.Context, bucket string, rules r2retention.RuleSet) error {
	return client.client.PutRulesWithBearer(ctx, bucket, rules, client.bearer)
}
func (client *boundR2Rules) Close() error {
	if client != nil {
		zeroCredential(client.bearer)
		client.bearer = nil
	}
	return nil
}

type boundR2Objects struct {
	client      r2.S3Client
	credentials r2.S3Credentials
	prefix      string
}

func (client *boundR2Objects) ListExact(ctx context.Context, generationID string) ([]r2retention.Object, error) {
	if !strings.HasSuffix(client.prefix, "/"+generationID) {
		return nil, errors.New("r2 retirement generation mismatch")
	}
	observation, err := client.client.Inventory(ctx, client.prefix, client.credentials, 1_000_000, 1<<50)
	if err != nil {
		return nil, err
	}
	result := make([]r2retention.Object, len(observation.Objects))
	for index, object := range observation.Objects {
		result[index] = r2retention.Object{Key: object.Key, Digest: object.Digest, Bytes: object.Bytes}
	}
	return result, nil
}
func (client *boundR2Objects) DeleteExact(ctx context.Context, key string) error {
	if key == "" || strings.HasPrefix(key, "/") || strings.Contains(key, "..") {
		return errors.New("r2 retirement key invalid")
	}
	return client.client.DeleteObject(ctx, strings.TrimSuffix(client.prefix, "/")+"/"+key, client.credentials)
}
func (client *boundR2Objects) Close() error {
	if client != nil {
		zeroCredential(client.credentials.AccessKeyID)
		zeroCredential(client.credentials.SecretAccessKey)
		zeroCredential(client.credentials.SessionToken)
		client.credentials = r2.S3Credentials{}
	}
	return nil
}

func NewLabsR2RetirementExecution(_ context.Context, profile serverconfig.Profile, authority *store.Store, _ generated.GateEvidence) (runengine.OffsiteRetirementExecution, error) {
	if profile.OffsiteBackup == nil || profile.LocalBackup == nil {
		return nil, errors.New("r2 retirement profile unavailable")
	}
	inspector, err := store.NewRestoredSQLiteInspector(authority)
	if err != nil {
		return nil, err
	}
	return backup.NewSQLRetirementExecution(authority, labsR2RetirementProviders{profile: profile.OffsiteBackup, local: profile.LocalBackup, authority: authority, inspector: inspector}, time.Now)
}

type labsR2RetirementCatalog struct {
	profile   *serverconfig.OffsiteBackup
	authority *store.Store
	resolver  *systemdCredentialResolver
	clock     func() time.Time
}

func (source *labsR2RetirementCatalog) CurrentOffsiteRetirementCatalog(ctx context.Context) (backup.OffsiteRetirementCatalog, error) {
	if source == nil || source.profile == nil || source.authority == nil || source.resolver == nil {
		return backup.OffsiteRetirementCatalog{}, errors.New("qualified G-008 offsite retirement catalog unavailable")
	}
	now := source.clock().UTC()
	gates := store.NewGateRepository(source.authority)
	evidence, err := gates.ResolveCurrentLiveGateEvidence(ctx, "G-008", source.profile.G008EvidenceDigest, source.profile.QualificationDigest, source.profile.PutCutoffDigest, source.profile.MultipartCutoffDigest, now)
	if err != nil {
		return backup.OffsiteRetirementCatalog{}, err
	}
	exclusiveDigest, err := gates.CurrentLiveExclusiveAdminDigest(ctx, "G-008", source.profile.G008EvidenceDigest, source.profile.QualificationDigest, source.profile.PutCutoffDigest, source.profile.MultipartCutoffDigest, now)
	if err != nil {
		return backup.OffsiteRetirementCatalog{}, err
	}
	secret, err := source.resolver.Resolve(ctx, credentialref.Reference{ID: source.profile.ObserverReferenceID, Consumer: "r2.retention.lock-admin"})
	if err != nil {
		return backup.OffsiteRetirementCatalog{}, err
	}
	defer func() {
		for index := range secret {
			secret[index] = 0
		}
	}()
	ruleSet, err := (r2.RetentionClient{AccountID: source.profile.AccountID, Bucket: source.profile.Bucket, Clock: source.clock}).ReadRulesWithBearer(ctx, source.profile.Bucket, secret)
	if err != nil || len(ruleSet.Rules) != source.profile.RuleCount {
		return backup.OffsiteRetirementCatalog{}, errors.New("qualified complete R2 rule catalog unavailable")
	}
	records, err := store.NewOffsiteRetirementRepository(source.authority).CurrentCatalogGenerations(ctx, evidence.RecoveryEpoch)
	if err != nil || len(records) < 2 {
		return backup.OffsiteRetirementCatalog{}, errors.New("durable offsite generation catalog unavailable")
	}
	catalog := backup.OffsiteRetirementCatalog{GenerationCreatedAt: map[string]time.Time{}, BucketID: source.profile.Bucket, G008BundleDigest: source.profile.G008EvidenceDigest,
		QualificationDigest: source.profile.QualificationDigest, PutCutoffDigest: source.profile.PutCutoffDigest, MultipartCutoffDigest: source.profile.MultipartCutoffDigest,
		ExclusiveAdminDigest: exclusiveDigest, RuleCount: len(ruleSet.Rules), RuleLimit: 1000, AvailableBytes: source.profile.AvailableBytes, ObservedAt: now,
		LockAdminReferenceID: source.profile.LockAdminReferenceID, LockAdminFingerprint: source.profile.LockAdminFingerprint, RetentionReferenceID: source.profile.RetentionReferenceID, RetentionFingerprint: source.profile.RetentionFingerprint}
	slices.SortFunc(ruleSet.Rules, func(a, b r2retention.Rule) int {
		if byID := strings.Compare(a.RuleID, b.RuleID); byID != 0 {
			return byID
		}
		return strings.Compare(a.Prefix, b.Prefix)
	})
	for _, rule := range ruleSet.Rules {
		catalog.CurrentRules = append(catalog.CurrentRules, backup.RetentionRuleRef{RuleID: rule.RuleID, Prefix: rule.Prefix})
	}
	catalog.RuleSetDigest = r2retention.DigestRuleSet(ruleSet)
	for _, record := range records {
		var generation backup.PendingOffsiteGeneration
		if json.Unmarshal(record.CanonicalJSON, &generation) != nil || generation.GenerationID != record.GenerationID || generation.SourcePointID != record.PointID {
			return backup.OffsiteRetirementCatalog{}, errors.New("durable offsite generation catalog corrupt")
		}
		catalog.Generations = append(catalog.Generations, generation)
		catalog.GenerationCreatedAt[generation.GenerationID] = record.CreatedAt
		catalog.TotalBytes += generation.ObjectBytes
		if record.Qualified {
			catalog.VerifiedPointIDs = append(catalog.VerifiedPointIDs, generation.SourcePointID)
		}
		if record.LastGood {
			catalog.LastGoodPointIDs = append(catalog.LastGoodPointIDs, generation.SourcePointID)
		}
	}
	if catalog.AvailableBytes > 0 {
		catalog.TotalBytes += catalog.AvailableBytes
	}
	body, _ := json.Marshal(struct {
		Generations []backup.PendingOffsiteGeneration
		Rules       []backup.RetentionRuleRef
		Epoch       int64
	}{catalog.Generations, catalog.CurrentRules, evidence.RecoveryEpoch})
	sum := sha256.Sum256(append([]byte("offsite-retirement-catalog-v1\x00"), body...))
	catalog.CatalogDigest = "sha256:" + hex.EncodeToString(sum[:])
	return catalog, nil
}

func NewProductionOffsiteRetirementCatalogFactory() OffsiteRetirementCatalogFactory {
	return func(_ context.Context, profile serverconfig.Profile, authority *store.Store) (api.OffsiteRetirementCatalogSource, error) {
		if profile.OffsiteBackup == nil || authority == nil {
			return api.UnavailableOffsiteRetirementCatalogSource{}, nil
		}
		resolver, err := newSystemdCredentialResolver(profile.SocketOwnerUID)
		if err != nil {
			return api.UnavailableOffsiteRetirementCatalogSource{}, nil
		}
		return &labsR2RetirementCatalog{profile: profile.OffsiteBackup, authority: authority, resolver: resolver, clock: time.Now}, nil
	}
}
