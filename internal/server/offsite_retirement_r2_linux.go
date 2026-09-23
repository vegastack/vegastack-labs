//go:build linux

package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

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

type labsR2RetirementProviders struct{ profile *serverconfig.OffsiteBackup }

func (providers labsR2RetirementProviders) Clients(_ context.Context, intent store.OffsiteRetirementIntent, lockAdmin, retention *credentialref.Value) (r2retention.RuleClient, r2retention.ObjectClient, error) {
	if providers.profile == nil || lockAdmin == nil || retention == nil || intent.BucketID != providers.profile.Bucket || intent.GenerationID == "" {
		return nil, nil, errors.New("r2 retirement provider binding unavailable")
	}
	credentials, err := r2.ParseParentS3Credentials(retention.Bytes())
	if err != nil {
		return nil, nil, err
	}
	rules := &boundR2Rules{client: r2.RetentionClient{AccountID: providers.profile.AccountID, Bucket: providers.profile.Bucket, Clock: time.Now}, bearer: append([]byte(nil), lockAdmin.Bytes()...)}
	objects := &boundR2Objects{client: r2.S3Client{Endpoint: providers.profile.Endpoint, Bucket: providers.profile.Bucket, Clock: time.Now}, credentials: credentials, prefix: strings.TrimSuffix(providers.profile.Prefix, "/") + "/" + intent.GenerationID}
	return rules, objects, nil
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

func NewLabsR2RetirementExecution(_ context.Context, profile serverconfig.Profile, authority *store.Store, _ generated.GateEvidence) (runengine.OffsiteRetirementExecution, error) {
	if profile.OffsiteBackup == nil {
		return nil, errors.New("r2 retirement profile unavailable")
	}
	return backup.NewSQLRetirementExecution(authority, labsR2RetirementProviders{profile: profile.OffsiteBackup}, time.Now)
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
		ExclusiveAdminDigest: exclusiveDigest, RuleCount: len(ruleSet.Rules), RuleLimit: 1000, AvailableBytes: source.profile.AvailableBytes, ObservedAt: now}
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
