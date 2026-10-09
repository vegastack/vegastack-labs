package store

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"

	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/stateexport"
)

func restoreRequestAuthorizationTargets(ctx context.Context, row discoveryRow, r generated.RestoreRequest, principal string) ([]authorization.Target, error) {
	var owners []authorization.Target
	if actor, err := adoptionGrant(ctx, row, r.PointID, "recovery-point", "author", "recovery.restore.author", true); err == nil {
		if actor != principal {
			return nil, actionError(generated.ErrorCodeAuthorizationDenied)
		}
	} else {
		policy, err := recoveryPointPolicy(row, r.PointID)
		if err != nil {
			return nil, err
		}
		owners = append(owners, authorization.Target{Capability: "recovery.restore.author", ResourceKind: "backup-policy", ResourceID: policy})
	}
	for _, host := range []string{r.FormerHostID, r.ReplacementHostID} {
		if host != "" {
			owners = append(owners, authorization.Target{Capability: "host.read", ResourceKind: "host", ResourceID: host})
		}
	}
	return owners, nil
}

// Initial restore drafts precede immutable qualification. Bind their internal
// typed request directly; later committed navigation resolves the stored plan.
func restoreDraftAuthorizationTargets(ctx context.Context, row discoveryRow, in DeclarationRevisionRequest) ([]authorization.Target, error) {
	r := in.RestoreRequest
	d := in.Document
	if r == nil || d.Status != "draft" || d.Revision != 1 || d.StateRevision != in.Expected.StateRevision+1 || r.ExpectedStateRevision != in.Expected.StateRevision || r.RecoveryEpoch != in.Expected.RecoveryEpoch || d.RecoveryEpoch != r.RecoveryEpoch || r.PointID != r.Source.PointID || r.PriorRecoveryEpoch != r.Source.RecoveryEpoch || r.NextRecoveryEpoch != r.PriorRecoveryEpoch+1 || r.PriorInstanceID == r.NewInstanceID || r.FormerHostID == r.ReplacementHostID || in.ReasonDigest != r.AuditDecisionDigest || len(d.Operations) != 2 || len(d.Extensions) != 1 || len(r.TargetIDs) == 0 {
		return nil, actionError(generated.ErrorCodeAuthorizationDenied)
	}
	raw, err := json.Marshal(r)
	if err != nil || generated.ValidateContractJSON(generated.SchemaIDRestoreRequest, raw, generated.ContractExact) != nil {
		return nil, actionError(generated.ErrorCodeInputInvalid)
	}
	fences := append([]generated.RestoreFenceItem(nil), r.Fences...)
	sort.Slice(fences, func(i, j int) bool {
		if fences[i].Boundary == fences[j].Boundary {
			return fences[i].SubjectID < fences[j].SubjectID
		}
		return fences[i].Boundary < fences[j].Boundary
	})
	_, sum, err := stateexport.CanonicalJSON(struct {
		Request generated.RestoreRequest
		Source  generated.RestoreSourceBinding
		Fences  []generated.RestoreFenceItem
		Audit   generated.RestoreAuditDecision
	}{*r, r.Source, fences, r.AuditDecision})
	digest := "sha256:" + hex.EncodeToString(sum[:])
	cutover := generated.DeclarationOperation{Sequence: 1, OperationID: "restore-cutover", OperationType: "recovery.restore.cutover", AdapterID: "core.recovery", TargetID: r.TargetIDs[0], InputDigest: digest, ArtifactDigest: r.CandidateDigest, Idempotent: false}
	canary := generated.DeclarationOperation{Sequence: 2, OperationID: r.CanaryStepID, OperationType: "recovery.canary.noop", AdapterID: "core.recovery", TargetID: r.NewInstanceID, InputDigest: r.CanaryBindingDigest, ArtifactDigest: r.CanaryBindingDigest, Idempotent: true}
	if err != nil || d.DeclarationID != "restore-"+strings.TrimPrefix(digest, "sha256:")[:32] || d.Operations[0] != cutover || d.Operations[1] != canary || d.Extensions[0] != (generated.ContractExtension{Name: "x-restore-binding", ValueDigest: digest}) {
		return nil, actionError(generated.ErrorCodeAuthorizationDenied)
	}
	return restoreRequestAuthorizationTargets(ctx, row, *r, in.Attribution.AuthenticatedPrincipalID)
}
