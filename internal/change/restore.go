package change

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/stateexport"
)

type RestoreDraftFacts struct {
	Request generated.RestoreRequest
	Source  generated.RestoreSourceBinding
	Fences  []generated.RestoreFenceItem
	Audit   generated.RestoreAuditDecision
}

// BuildRestoreChange constructs only an inert draft. It performs no store,
// filesystem, adapter, or authority mutation.
func BuildRestoreChange(ctx context.Context, request generated.RestoreRequest, source generated.RestoreSourceBinding, fences []generated.RestoreFenceItem, decision generated.RestoreAuditDecision) (generated.DeclarationRevision, error) {
	canaryDigest, canaryErr := RestoreCanaryBindingDigest(request)
	if ctx == nil || ctx.Err() != nil || canaryErr != nil || canaryDigest != request.CanaryBindingDigest || !exactRestoreValue(generated.SchemaIDRestoreRequest, request) || !exactRestoreValue(generated.SchemaIDRestoreSourceBinding, source) || !exactRestoreValue(generated.SchemaIDRestoreAuditDecision, decision) || !sameJSON(request.Source, source) || !sameJSON(request.AuditDecision, decision) || request.PointID != source.PointID || request.PriorRecoveryEpoch != source.RecoveryEpoch || request.NextRecoveryEpoch != request.PriorRecoveryEpoch+1 || request.PriorInstanceID == request.NewInstanceID || request.FormerHostID == request.ReplacementHostID || len(fences) == 0 || len(fences) != len(request.Fences) {
		return generated.DeclarationRevision{}, inputError()
	}
	ordered := append([]generated.RestoreFenceItem(nil), fences...)
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].Boundary == ordered[j].Boundary {
			return ordered[i].SubjectID < ordered[j].SubjectID
		}
		return ordered[i].Boundary < ordered[j].Boundary
	})
	for i := range ordered {
		if !exactRestoreValue(generated.SchemaIDRestoreFenceItem, ordered[i]) {
			return generated.DeclarationRevision{}, inputError()
		}
	}
	bindingDigest, err := RestoreBindingDigest(request, source, ordered, decision)
	if err != nil {
		return generated.DeclarationRevision{}, inputError()
	}
	targetID := request.TargetIDs[0]
	createdAt := source.VerifiedAt
	if _, err := time.Parse(time.RFC3339, createdAt); err != nil {
		return generated.DeclarationRevision{}, inputError()
	}
	operation := generated.DeclarationOperation{Sequence: 1, OperationID: "restore-cutover", OperationType: "recovery.restore.cutover", AdapterID: "core.recovery", TargetID: targetID, InputDigest: bindingDigest, ArtifactDigest: request.CandidateDigest, Idempotent: false}
	canary := generated.DeclarationOperation{Sequence: 2, OperationID: request.CanaryStepID, OperationType: "recovery.canary.noop", AdapterID: "core.recovery", TargetID: request.NewInstanceID, InputDigest: request.CanaryBindingDigest, ArtifactDigest: request.CanaryBindingDigest, Idempotent: true}
	extensions := []generated.ContractExtension{{Name: "x-restore-binding", ValueDigest: bindingDigest}}
	semantic := struct {
		DeclarationID, DeclarationType string
		Operations                     []generated.DeclarationOperation
		ReasonDigest                   string
		Extensions                     []generated.ContractExtension
	}{
		"restore-" + strings.TrimPrefix(bindingDigest, "sha256:")[:32], "recovery.restore", []generated.DeclarationOperation{operation, canary}, request.AuditDecisionDigest, extensions,
	}
	_, content, err := stateexport.CanonicalJSON(semantic)
	if err != nil {
		return generated.DeclarationRevision{}, inputError()
	}
	document := generated.DeclarationRevision{Schema: generated.SchemaIDDeclarationRevision, SchemaVersion: "1.0.0", DeclarationID: semantic.DeclarationID, DeclarationType: semantic.DeclarationType, Revision: 1, StateRevision: request.ExpectedStateRevision + 1, RecoveryEpoch: request.RecoveryEpoch, ContentDigest: "sha256:" + hex.EncodeToString(content[:]), Status: "draft", Operations: semantic.Operations, CreatedAt: createdAt, CreatedBy: "recovery-operator", AgentSessionID: "recovery-plan", Extensions: extensions}
	raw, err := json.Marshal(document)
	if err != nil || generated.ValidateContractJSON(generated.SchemaIDDeclarationRevision, raw, generated.ContractExact) != nil {
		return generated.DeclarationRevision{}, inputError()
	}
	return document, nil
}

// RestoreCanaryBindingDigest seals the exact subordinate no-op identifiers
// and authority target before the enclosing restore plan is acknowledged.
func RestoreCanaryBindingDigest(request generated.RestoreRequest) (string, error) {
	value := struct {
		Domain                                        string
		CanaryRunID, CanaryStepID, CanaryLeaseID      string
		NewInstanceID                                 string
		NextRecoveryEpoch                             int64
		TargetDigest, FenceSetDigest, CandidateDigest string
	}{"vegastack-labs.dev/recovery-subordinate-canary/v1", request.CanaryRunID, request.CanaryStepID, request.CanaryLeaseID, request.NewInstanceID, request.NextRecoveryEpoch, request.TargetDigest, request.FenceSetDigest, request.CandidateDigest}
	_, sum, err := stateexport.CanonicalJSON(value)
	if err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func RestoreBindingDigest(request generated.RestoreRequest, source generated.RestoreSourceBinding, fences []generated.RestoreFenceItem, decision generated.RestoreAuditDecision) (string, error) {
	ordered := append([]generated.RestoreFenceItem(nil), fences...)
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].Boundary == ordered[j].Boundary {
			return ordered[i].SubjectID < ordered[j].SubjectID
		}
		return ordered[i].Boundary < ordered[j].Boundary
	})
	_, sum, err := stateexport.CanonicalJSON(RestoreDraftFacts{Request: request, Source: source, Fences: ordered, Audit: decision})
	if err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func exactRestoreValue(schema string, value any) bool {
	raw, err := json.Marshal(value)
	return err == nil && generated.ValidateContractJSON(schema, raw, generated.ContractExact) == nil
}
func sameJSON(left, right any) bool {
	a, _ := json.Marshal(left)
	b, _ := json.Marshal(right)
	return string(a) == string(b)
}
