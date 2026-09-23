//go:build linux

package r2

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"runtime"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/backup"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type RetirementSurvivorVerificationConfig struct {
	Authority                                                      *store.Store
	Intent                                                         store.OffsiteRetirementIntent
	Binding                                                        adapter.ExactExecutionBinding
	Endpoint, Bucket, Prefix, ParentReferenceID, ParentFingerprint string
	ResticBinaryPath, CustodyPolicyPath                            string
	Parent, RepositoryKey                                          *credentialref.Value
	Inspector                                                      store.RestoredSQLiteInspector
	Clock                                                          func() time.Time
}

type retirementReadAuthority struct {
	repository            *store.OffsiteRetirementRepository
	intent                store.OffsiteRetirementIntent
	binding               adapter.ExactExecutionBinding
	pointID, generationID string
	clock                 func() time.Time
}

func (a retirementReadAuthority) VerifyWriterLease(lease backup.WriterLease, at time.Time) error {
	if lease.PlanID != a.binding.PlanID || lease.PlanDigest != a.binding.PlanDigest || lease.RunID != a.binding.RunID || lease.StepID != a.binding.StepID || lease.LeaseID != "retirement-"+a.binding.LeaseID || lease.PointID != a.pointID || lease.TargetID != a.generationID || lease.RecoveryEpoch != a.binding.RecoveryEpoch {
		return errors.New("retirement survivor lease mismatch")
	}
	return a.repository.VerifySurvivorReadLease(context.Background(), a.intent.IntentID, lease.LeaseID, lease.RunID, lease.StepID, a.pointID, a.generationID, lease.RecoveryEpoch, at)
}
func (a retirementReadAuthority) BeginCustody(context.Context, backup.CustodySession) error {
	return a.repository.VerifySurvivorReadLease(context.Background(), a.intent.IntentID, "retirement-"+a.binding.LeaseID, a.binding.RunID, a.binding.StepID, a.pointID, a.generationID, a.binding.RecoveryEpoch, a.clock().UTC())
}
func (a retirementReadAuthority) FinishCustody(context.Context, backup.CustodySession, string) error {
	return nil
}

func VerifyRetirementSurvivor(ctx context.Context, config RetirementSurvivorVerificationConfig, pointID string) (backup.OffsiteSurvivorProof, error) {
	if config.Authority == nil || config.Parent == nil || config.RepositoryKey == nil || config.Inspector == nil || config.Clock == nil || pointID == "" {
		return backup.OffsiteSurvivorProof{}, errors.New("retirement survivor verification unavailable")
	}
	var key store.OffsiteRetirementSurvivorKey
	for _, candidate := range config.Intent.SurvivorKeyReferences {
		if candidate.PointID == pointID {
			key = candidate
		}
	}
	if key.ReferenceID == "" {
		return backup.OffsiteSurvivorProof{}, errors.New("retirement survivor key unavailable")
	}
	spec, err := store.NewOffsiteRepository(config.Authority).RunSpec(ctx, key.GenerationID)
	if err != nil || spec.RepositoryKeyReferenceID != key.ReferenceID || spec.SourcePointID != pointID {
		return backup.OffsiteSurvivorProof{}, errors.New("retirement survivor run spec mismatch")
	}
	source, err := store.NewBackupRepository(config.Authority).GetVerifiedCriticalOffsiteSource(ctx, pointID)
	if err != nil {
		return backup.OffsiteSurvivorProof{}, err
	}
	var expectedSnapshotID string
	generations, err := store.NewOffsiteRetirementRepository(config.Authority).CurrentCatalogGenerations(ctx, config.Intent.RecoveryEpoch)
	if err != nil {
		return backup.OffsiteSurvivorProof{}, err
	}
	for _, record := range generations {
		if record.GenerationID != key.GenerationID || record.PointID != pointID {
			continue
		}
		var pending backup.PendingOffsiteGeneration
		if json.Unmarshal(record.CanonicalJSON, &pending) != nil || pending.GenerationID != key.GenerationID || pending.SourcePointID != pointID {
			return backup.OffsiteSurvivorProof{}, errors.New("retirement survivor catalog corrupt")
		}
		expectedSnapshotID = pending.OffsiteSnapshotID
	}
	if expectedSnapshotID == "" {
		return backup.OffsiteSurvivorProof{}, errors.New("retirement survivor snapshot unavailable")
	}
	deadline, err := time.Parse(time.RFC3339, config.Binding.MaximumExpiresAt)
	if err != nil || !config.Clock().UTC().Before(deadline) {
		return backup.OffsiteSurvivorProof{}, errors.New("retirement survivor deadline invalid")
	}
	request := adapter.SessionRequest{RunID: config.Binding.RunID, StepID: config.Binding.StepID, PointID: pointID, GenerationID: key.GenerationID, RecoveryEpoch: config.Binding.RecoveryEpoch, Prefix: config.Prefix + "/" + key.GenerationID + "/", Actions: []string{"GetObject", "HeadObject", "ListObjectsV2"}, Deadline: deadline, TTL: time.Duration(spec.SessionTTLSeconds) * time.Second, ParentReferenceID: config.ParentReferenceID, ParentFingerprint: config.ParentFingerprint}
	bearer := make([]byte, 32)
	if _, err := rand.Read(bearer); err != nil {
		return backup.OffsiteSurvivorProof{}, err
	}
	defer zeroBytes(bearer)
	endpoint, iamURI, err := serveOneRunEndpoint(SessionIssuer{Signer: LocalSigner{Endpoint: config.Endpoint, Bucket: config.Bucket, Clock: config.Clock}, Clock: config.Clock, ParentReferenceID: config.ParentReferenceID, ParentFingerprint: config.ParentFingerprint}, config.Parent, request, bearer, config.Clock, nil, nil)
	if err != nil {
		return backup.OffsiteSurvivorProof{}, err
	}
	defer endpoint.Close()
	lease := backup.WriterLease{PlanID: config.Binding.PlanID, PlanDigest: config.Binding.PlanDigest, RunID: config.Binding.RunID, StepID: config.Binding.StepID, LeaseID: "retirement-" + config.Binding.LeaseID, RepositoryID: key.GenerationID, RepositoryClass: "critical-offsite", PointID: pointID, TargetID: key.GenerationID, SourceRevision: spec.SourceRevision, RecoveryEpoch: config.Binding.RecoveryEpoch, MaximumExpiresAt: deadline}
	authority := retirementReadAuthority{repository: store.NewOffsiteRetirementRepository(config.Authority), intent: config.Intent, binding: config.Binding, pointID: pointID, generationID: key.GenerationID, clock: config.Clock}
	session := backup.CustodySession{ProtocolVersion: backup.CustodyProtocolVersion, Role: "offsite-verifier", PlanID: config.Binding.PlanID, PlanDigest: config.Binding.PlanDigest, RunID: config.Binding.RunID, StepID: config.Binding.StepID, LeaseID: lease.LeaseID, RepositoryID: key.GenerationID, RepositoryClass: "critical-offsite", GenerationID: key.GenerationID, OffsiteRepositoryURL: spec.RepositoryURL, PointID: pointID, SourceID: "retirement-survivor", SourceRevision: spec.SourceRevision, RecoveryEpoch: config.Binding.RecoveryEpoch, MaximumExpiresAt: deadline, MaximumObjects: spec.MaximumPUTs, MaximumBytes: spec.MaximumBytes, WriterLease: &lease}
	launcher := backup.CustodyLauncher{PolicyPath: config.CustodyPolicyPath, Writer: authority, Journal: authority, Clock: config.Clock}
	client, err := launcher.Start(ctx, session)
	if err != nil {
		return backup.OffsiteSurvivorProof{}, err
	}
	requestRestic := backup.OffsiteResticRequest{BinaryPath: config.ResticBinaryPath, Architecture: runtime.GOARCH, RepositoryURL: spec.RepositoryURL, SnapshotPath: spec.SnapshotPath, PasswordFDPath: "/proc/self/fd/3", IAMURI: iamURI, AuthorizationTokenFDPath: "/proc/self/fd/4", RunID: config.Binding.RunID, StepID: config.Binding.StepID, PointID: pointID, GenerationID: key.GenerationID, RecoveryEpoch: config.Binding.RecoveryEpoch, VerificationOnly: true, IsolatedRestore: true}
	requestRestic.Arguments = []string{requestRestic.BinaryPath, "-r", requestRestic.RepositoryURL, "--json", "--no-cache", "--password-file", requestRestic.PasswordFDPath, "check", "--read-data"}
	requestRestic.Environment = []string{"HOME=/nonexistent", "RESTIC_PASSWORD_FILE=" + requestRestic.PasswordFDPath, "AWS_CONTAINER_CREDENTIALS_FULL_URI=" + requestRestic.IAMURI, "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE=" + requestRestic.AuthorizationTokenFDPath}
	result, runErr := client.RunOffsiteRestic(ctx, requestRestic, config.RepositoryKey, bearer)
	closeErr := client.Close(context.WithoutCancel(ctx))
	endpoint.MarkChildExited()
	if runErr != nil || closeErr != nil || !result.ChildExited || result.FullReadAt.IsZero() || result.RestoredAt.IsZero() || result.RestoreTarget == "" || len(result.SnapshotIDs) != 1 || result.SnapshotIDs[0] != expectedSnapshotID {
		return backup.OffsiteSurvivorProof{}, errors.New("retirement survivor restic verification failed")
	}
	defer os.RemoveAll(result.RestoreTarget)
	restoreDigest, err := backup.VerifyOffsiteRestoredSnapshot(ctx, result.RestoreTarget, spec.SnapshotPath, source.ManifestJSON, source.ManifestDigest, result.RestoredAt, config.Inspector, uint32(os.Geteuid()))
	if err != nil {
		return backup.OffsiteSurvivorProof{}, err
	}
	fullBody, _ := json.Marshal(struct {
		GenerationID string
		Snapshots    []string
		At           time.Time
	}{key.GenerationID, result.SnapshotIDs, result.FullReadAt})
	fullSum := sha256.Sum256(append([]byte("offsite-full-read-v1\x00"), fullBody...))
	expected, err := store.NewOffsiteRetirementRepository(config.Authority).ExpectedOffsiteSurvivor(ctx, pointID)
	if err != nil {
		return backup.OffsiteSurvivorProof{}, err
	}
	now := config.Clock().UTC()
	return backup.OffsiteSurvivorProof{PointID: pointID, GenerationID: key.GenerationID, RuleDigest: expected.RuleDigest, InventoryDigest: expected.InventoryDigest, FullReadDigest: "sha256:" + hex.EncodeToString(fullSum[:]), RestoreDigest: restoreDigest, FullReadAt: result.FullReadAt, RestoredAt: result.RestoredAt, ObservedAt: now, RecoveryEpoch: config.Intent.RecoveryEpoch}, nil
}
