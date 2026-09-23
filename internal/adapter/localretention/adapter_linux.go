//go:build linux

package localretention

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"runtime"
	"sort"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/backup"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/store"
)

const AdapterID = "local.retention"
const OperationType = "backup.local.retire"

type Config struct {
	LocalBackup *serverconfig.LocalBackup
	ExpectedUID uint32
	Backups     *store.BackupRepository
	Retirements *store.LocalRetirementRepository
	Inspector   store.RestoredSQLiteInspector
	Clock       func() time.Time
}
type Adapter struct{ config Config }

func New(config Config) (*Adapter, error) {
	if config.LocalBackup == nil || config.Backups == nil || config.Retirements == nil || config.Inspector == nil {
		return nil, retentionError(generated.ErrorCodePrerequisiteBlocked, "local-retention")
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	return &Adapter{config}, nil
}
func (*Adapter) Execute(context.Context, adapter.Operation) (adapter.Effect, error) {
	return adapter.Effect{}, retentionError(generated.ErrorCodePrerequisiteBlocked, "local-retention-credential-required")
}
func (*Adapter) ExecuteWithCredentials(context.Context, adapter.Operation, []*credentialref.Value) (adapter.Effect, error) {
	return adapter.Effect{}, retentionError(generated.ErrorCodePrerequisiteBlocked, "local-retention-binding-required")
}
func (a *Adapter) Verify(ctx context.Context, op adapter.Operation, effect adapter.Effect) (adapter.Verification, error) {
	if op.OperationType != OperationType || op.AdapterID != AdapterID || effect.Status != "succeeded" || effect.ResultDigest == "" || effect.PendingPointID == nil {
		return adapter.Verification{}, retentionError(generated.ErrorCodeIntegrityFailure, "local-retention-verify")
	}
	if err := a.config.Retirements.LocalRetirementVerified(ctx, *effect.PendingPointID, effect.ResultDigest); err != nil {
		return adapter.Verification{}, err
	}
	return adapter.Verification{Verified: true, Digest: effect.ResultDigest}, nil
}
func (a *Adapter) ExecuteBoundWithCredentials(ctx context.Context, op adapter.Operation, binding adapter.ExactExecutionBinding, values []*credentialref.Value) (effect adapter.Effect, outcomeErr error) {
	if adapter.ValidateOperation(op) != nil || op.OperationType != OperationType || op.AdapterID != AdapterID || len(values) != 1 || values[0] == nil || len(op.SecretReferences) != 1 || op.SecretReferences[0].Consumer != AdapterID {
		return effect, retentionError(generated.ErrorCodePrerequisiteBlocked, "local-retention-binding")
	}
	intent, err := a.config.Retirements.GetLocalRetirementIntentBySelection(ctx, op.InputDigest)
	if err != nil {
		return effect, err
	}
	if intent.Request.ExpectedInventoryDigest != op.ArtifactDigest || intent.Request.RepositoryID != op.TargetID || intent.Request.StateRevision != binding.StateRevision || intent.Request.RecoveryEpoch != binding.RecoveryEpoch {
		return effect, retentionError(generated.ErrorCodePlanStale, "local-retention-intent")
	}
	deadline, err := time.Parse(time.RFC3339, binding.MaximumExpiresAt)
	if err != nil || !a.config.Clock().Before(deadline) {
		return effect, retentionError(generated.ErrorCodePlanStale, "local-retention-deadline")
	}
	policy, err := backup.LoadCustodyPolicy(a.config.LocalBackup.CustodyPolicyPath)
	if err != nil {
		return effect, retentionError(generated.ErrorCodePrerequisiteBlocked, "local-retention-custody-policy")
	}
	attribution := audit.Attribution{AuthenticatedPrincipalID: "local-retention-custodian", AuthenticatedPrincipalMethod: "internal"}
	lease, err := a.config.Retirements.ClaimLocalRetirement(ctx, store.LocalRetirementClaimRequest{IntentID: intent.IntentID, LeaseID: binding.LeaseID, PlanID: binding.PlanID, PlanDigest: binding.PlanDigest, RunID: binding.RunID, StepID: binding.StepID, ExecutorLeaseID: binding.LeaseID, RetentionConsumerID: "backup-retention", RecoveryEpoch: binding.RecoveryEpoch, MaximumExpiresAt: deadline, Attribution: attribution})
	if err != nil {
		return effect, err
	}
	root := a.config.LocalBackup.StandardRoot
	if intent.Request.RepositoryClass == "critical" {
		root = a.config.LocalBackup.CriticalRoot
	}
	planned := make([]string, len(intent.Request.Targets))
	for i, t := range intent.Request.Targets {
		planned[i] = t.SnapshotID
	}
	sort.Strings(planned)
	retentionLease := backup.RetentionLease{LeaseID: lease.LeaseID, RepositoryID: lease.RepositoryID, RecoveryEpoch: lease.RecoveryEpoch, MaximumExpiresAt: lease.MaximumExpiresAt, MaxMutations: lease.MaxWorkObjects, MaxMutationBytes: lease.MaxMutationBytes, PlannedSnapshotIDs: planned}
	authority := &retentionAuthority{repository: a.config.Retirements, lease: retentionLease, attribution: attribution}
	session := backup.CustodySession{ProtocolVersion: backup.CustodyProtocolVersion, Role: "retention", PlanID: binding.PlanID, PlanDigest: binding.PlanDigest, RunID: binding.RunID, StepID: binding.StepID, LeaseID: lease.LeaseID, RepositoryID: lease.RepositoryID, RepositoryClass: lease.RepositoryClass, PointID: intent.IntentID, SourceID: intent.IntentID, SourceRevision: lease.SourceRevision, RecoveryEpoch: lease.RecoveryEpoch, MaximumExpiresAt: lease.MaximumExpiresAt, MaximumObjects: lease.MaxWorkObjects, MaximumBytes: lease.MaxMutationBytes, RetentionLease: &retentionLease}
	launcher := backup.CustodyLauncher{PolicyPath: a.config.LocalBackup.CustodyPolicyPath, Retention: authority, Mutations: authority, Journal: authority, Clock: a.config.Clock}
	custody, err := launcher.Start(ctx, session)
	if err != nil {
		return effect, retentionError(generated.ErrorCodePrerequisiteBlocked, "local-retention-custody")
	}
	closed := false
	defer func() {
		if !closed {
			closeErr := custody.Close(context.WithoutCancel(ctx))
			if closeErr == nil {
				return
			}
			effect = adapter.Effect{EffectObserved: true}
			outcomeErr = retentionError(generated.ErrorCodeRecoveryRequired, "local-retention-custody-close")
		}
	}()
	base := backup.ResticRequest{BinaryPath: a.config.LocalBackup.ResticBinaryPath, Architecture: runtime.GOARCH, RepositoryID: lease.RepositoryID, RepositoryClass: lease.RepositoryClass, RepositoryRoot: root, ExchangeRoot: policy.ExchangeRoot, ExecutionUID: policy.ResticUID, ExecutionGID: policy.ResticUID, ControllerUID: a.config.ExpectedUID, OutputLimit: 4 << 20}
	pre, err := custody.RunRestic(ctx, withMode(base, "snapshots"), values[0])
	if err != nil || !sameIDs(pre.SnapshotIDs, allSnapshotIDs(intent)) {
		return adapter.Effect{}, retentionError(generated.ErrorCodePlanStale, "local-retention-inventory")
	}
	preObjects, err := custody.Inventory(ctx)
	if err != nil || backup.ExpectedInventoryDigest(preObjects) != intent.Request.ExpectedInventoryDigest {
		return adapter.Effect{}, retentionError(generated.ErrorCodePlanStale, "local-retention-object-inventory")
	}
	dry := withMode(base, "forget-dry-run")
	dry.SnapshotIDs = planned
	if _, err = custody.RunRestic(ctx, dry, values[0]); err != nil {
		return effect, retentionError(generated.ErrorCodeExecutionFailed, "local-retention-dry-run")
	}
	forget := withMode(base, "forget")
	forget.SnapshotIDs = planned
	if _, err = custody.RunRestic(ctx, forget, values[0]); err != nil {
		return adapter.Effect{EffectObserved: true}, retentionError(generated.ErrorCodeRecoveryRequired, "local-retention-forget")
	}
	prune := withMode(base, "prune")
	prune.MaxRepackBytes = lease.MaxRepackBytes
	if _, err = custody.RunRestic(ctx, prune, values[0]); err != nil {
		return adapter.Effect{EffectObserved: true}, retentionError(generated.ErrorCodeRecoveryRequired, "local-retention-prune")
	}
	post, err := custody.RunRestic(ctx, withMode(base, "snapshots"), values[0])
	if err != nil || !sameIDs(post.SnapshotIDs, survivorSnapshotIDs(intent)) {
		return adapter.Effect{EffectObserved: true}, retentionError(generated.ErrorCodeRecoveryRequired, "local-retention-post-inventory")
	}
	objects, err := custody.Inventory(ctx)
	if err != nil {
		return adapter.Effect{EffectObserved: true}, retentionError(generated.ErrorCodeRecoveryRequired, "local-retention-object-inventory")
	}
	preBytes, preBytesOK := inventoryBytes(preObjects)
	postBytes, postBytesOK := inventoryBytes(objects)
	if !preBytesOK || !postBytesOK || postBytes > preBytes {
		return adapter.Effect{EffectObserved: true}, retentionError(generated.ErrorCodeRecoveryRequired, "local-retention-reclaim")
	}
	if _, err = custody.RunRestic(ctx, withMode(base, "check-full"), values[0]); err != nil {
		return adapter.Effect{EffectObserved: true}, retentionError(generated.ErrorCodeRecoveryRequired, "local-retention-full-read")
	}
	runner := custodyRunner{custody}
	proofParts := []string{}
	survivorIDs := []string{}
	for _, survivor := range intent.Request.Survivors {
		point, e := a.config.Backups.GetPendingRecoveryPoint(ctx, survivor.PointID)
		if e != nil {
			return adapter.Effect{EffectObserved: true}, e
		}
		var manifest backup.CreationManifest
		if json.Unmarshal(point.ManifestJSON, &manifest) != nil {
			return adapter.Effect{EffectObserved: true}, retentionError(generated.ErrorCodeIntegrityFailure, "local-retention-manifest")
		}
		observed, e := custody.InventoryExpected(ctx, manifest.ExpectedObjects)
		if e != nil {
			return adapter.Effect{EffectObserved: true}, e
		}
		inventory, e := backup.VerifyCustodyInventory(manifest, point.ManifestDigest, observed)
		if e != nil {
			return adapter.Effect{EffectObserved: true}, e
		}
		proof, e := backup.VerifyFunctionalRestore(ctx, inventory, manifest, runner, base, values[0], a.config.Inspector)
		if e != nil {
			return adapter.Effect{EffectObserved: true}, e
		}
		proofParts = append(proofParts, proof.ManifestDigest, proof.InventoryDigest, proof.ContentDigest)
		survivorIDs = append(survivorIDs, survivor.PointID)
	}
	inventoryDigest := backup.ExpectedInventoryDigest(objects)
	journalDigest, err := a.config.Retirements.LocalRetirementJournalDigest(ctx, lease.LeaseID)
	if err != nil {
		return adapter.Effect{EffectObserved: true}, err
	}
	proofDigest := digest("retirement-survivors", proofParts...)
	closeErr := custody.Close(ctx)
	closed = true
	if closeErr != nil {
		return adapter.Effect{EffectObserved: true}, retentionError(generated.ErrorCodeRecoveryRequired, "local-retention-custody-close")
	}
	generation, err := a.config.Retirements.CommitLocalRetirementSuccess(ctx, store.LocalRetirementSettlement{IntentID: intent.IntentID, LeaseID: lease.LeaseID, SuccessorInventoryDigest: inventoryDigest, JournalDigest: journalDigest, SurvivorProofDigest: proofDigest, SurvivorPointIDs: survivorIDs, MeasuredReclaimBytes: preBytes - postBytes, RecoveryEpoch: lease.RecoveryEpoch})
	if err != nil {
		return adapter.Effect{EffectObserved: true}, err
	}
	id := intent.IntentID
	return adapter.Effect{Status: "succeeded", ResultDigest: generation, PendingPointID: &id, Changed: true, EffectObserved: true}, nil
}

type custodyRunner struct{ backup.CustodyClient }

func (c custodyRunner) Run(ctx context.Context, request backup.ResticRequest, value *credentialref.Value) (backup.ResticResult, error) {
	return c.RunRestic(ctx, request, value)
}

func (c custodyRunner) Observation() backup.ResticObservation        { return c.ResticObservation() }
func withMode(r backup.ResticRequest, m string) backup.ResticRequest { r.Mode = m; return r }
func allSnapshotIDs(i store.LocalRetirementIntent) []string {
	return append(survivorSnapshotIDs(i), targetSnapshotIDs(i)...)
}
func targetSnapshotIDs(i store.LocalRetirementIntent) []string {
	r := []string{}
	for _, v := range i.Request.Targets {
		r = append(r, v.SnapshotID)
	}
	return r
}
func survivorSnapshotIDs(i store.LocalRetirementIntent) []string {
	r := []string{}
	for _, v := range i.Request.Survivors {
		r = append(r, v.SnapshotID)
	}
	return r
}
func sameIDs(a, b []string) bool {
	a = append([]string(nil), a...)
	b = append([]string(nil), b...)
	sort.Strings(a)
	sort.Strings(b)
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
func inventoryBytes(objects []backup.ExpectedObject) (int64, bool) {
	var total int64
	for _, object := range objects {
		if object.Bytes < 0 || object.Bytes > int64(^uint64(0)>>1)-total {
			return 0, false
		}
		total += object.Bytes
	}
	return total, true
}
func digest(domain string, parts ...string) string {
	h := sha256.New()
	h.Write([]byte(domain))
	for _, p := range parts {
		h.Write([]byte{0})
		h.Write([]byte(p))
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}
func retentionError(code, target string) error { return failure.New(code, target, false) }

type retentionAuthority struct {
	repository  *store.LocalRetirementRepository
	lease       backup.RetentionLease
	attribution audit.Attribution
}

func (a *retentionAuthority) VerifyRetentionLease(_ backup.RetentionLease, now time.Time) error {
	return a.repository.VerifyLocalRetirementLease(context.Background(), a.lease.LeaseID, a.lease.RecoveryEpoch, now)
}
func (a *retentionAuthority) BeginRetainedMutation(ctx context.Context, m backup.RetainedMutationAttempt) error {
	return a.repository.BeginLocalMutation(ctx, store.LocalRetirementMutationAttempt{MutationID: m.MutationID, LeaseID: m.LeaseID, MutationKind: m.MutationKind, ObjectType: m.ObjectType, ObjectName: m.ObjectName, ObjectDigest: m.Digest, Sequence: m.Sequence, ObjectBytes: m.Bytes, RecoveryEpoch: m.RecoveryEpoch, Attribution: a.attribution})
}
func (a *retentionAuthority) FinishRetainedMutation(ctx context.Context, m backup.RetainedMutationOutcome) error {
	return a.repository.FinishLocalMutation(ctx, store.LocalRetirementMutationOutcome{MutationID: m.MutationID, LeaseID: m.LeaseID, Status: m.Status, QuarantineName: m.QuarantineName, Attribution: a.attribution})
}
func (a *retentionAuthority) BeginCustody(ctx context.Context, s backup.CustodySession) error {
	return a.repository.BeginRetirementCustody(ctx, s.LeaseID, s.NonceDigest)
}
func (a *retentionAuthority) FinishCustody(ctx context.Context, s backup.CustodySession, outcome string) error {
	return a.repository.FinishRetirementCustody(ctx, s.NonceDigest, outcome)
}
