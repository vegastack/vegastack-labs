package gate

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/store"
)

func ValidateGateOperations(operations []generated.DeclarationOperation, central bool) error {
	gateCount := 0
	for _, operation := range operations {
		if strings.HasPrefix(operation.OperationType, "gate.") || operation.AdapterID == "core.gate" {
			gateCount++
			if operation.AdapterID != "core.gate" || operation.InputDigest != operation.ArtifactDigest || !central {
				return errors.New("gate operation lacks central exact-digest binding")
			}
			switch operation.OperationType {
			case "gate.evidence.apply", "gate.evidence.supersede", "gate.evidence.revoke", "gate.profile.bind":
			default:
				return errors.New("unsupported gate operation")
			}
		}
	}
	if gateCount > 0 && (gateCount != 1 || len(operations) != 1) {
		return errors.New("gate changes must contain one operation")
	}
	return nil
}

func HasGateOperation(operations []generated.DeclarationOperation) bool {
	for _, operation := range operations {
		if strings.HasPrefix(operation.OperationType, "gate.") || operation.AdapterID == "core.gate" {
			return true
		}
	}
	return false
}

// BuildEvidenceChange authors an inert, one-operation declaration. Its input
// digest is the server-stored draft digest; the run effect must reload it.
func BuildEvidenceChange(draft store.GateDraft, expected store.RevisionToken) (generated.DeclarationRevisionRequest, error) {
	if draft.EvidenceID == "" || draft.GateID == "" || draft.SubjectID == "" || draft.BundleDigest == "" || draft.StateRevision != expected.StateRevision || draft.RecoveryEpoch != expected.RecoveryEpoch {
		return generated.DeclarationRevisionRequest{}, errors.New("gate draft is not current")
	}
	if draft.SupersedesEvidenceID != nil && draft.RevokesEvidenceID != nil {
		return generated.DeclarationRevisionRequest{}, errors.New("ambiguous gate relation")
	}
	operationType := "gate.evidence.apply"
	if draft.SupersedesEvidenceID != nil {
		operationType = "gate.evidence.supersede"
	}
	if draft.RevokesEvidenceID != nil {
		operationType = "gate.evidence.revoke"
	}
	request := generated.DeclarationRevisionRequest{
		Schema: generated.SchemaIDDeclarationRevisionRequest, SchemaVersion: "1.0.0",
		DeclarationID: "gate-evidence-" + draft.EvidenceID, DeclarationType: "gate-evidence",
		ExpectedRevision: 1, ExpectedStateRevision: expected.StateRevision, RecoveryEpoch: expected.RecoveryEpoch,
		Operations:   []generated.DeclarationOperation{{Sequence: 1, OperationID: draft.EvidenceID, OperationType: operationType, AdapterID: "core.gate", TargetID: draft.SubjectID, InputDigest: draft.BundleDigest, ArtifactDigest: draft.BundleDigest, Idempotent: true}},
		ReasonDigest: draft.BundleDigest, Extensions: []generated.ContractExtension{},
	}
	raw, err := json.Marshal(request)
	if err != nil || generated.ValidateContractJSON(generated.SchemaIDDeclarationRevisionRequest, raw, generated.ContractExact) != nil {
		return generated.DeclarationRevisionRequest{}, errors.New("gate change contract invalid")
	}
	return request, nil
}

func BuildProfileChange(draft store.ProfileDraft, expected store.RevisionToken) (generated.DeclarationRevisionRequest, error) {
	if draft.BindingID == "" || draft.Scope.ProfileID == "" || draft.ScopeDigest == "" || draft.StateRevision != expected.StateRevision || draft.RecoveryEpoch != expected.RecoveryEpoch {
		return generated.DeclarationRevisionRequest{}, errors.New("profile draft is not current")
	}
	request := generated.DeclarationRevisionRequest{
		Schema: generated.SchemaIDDeclarationRevisionRequest, SchemaVersion: "1.0.0",
		DeclarationID: "gate-profile-" + draft.BindingID, DeclarationType: "gate-profile",
		ExpectedRevision: 1, ExpectedStateRevision: expected.StateRevision, RecoveryEpoch: expected.RecoveryEpoch,
		Operations:   []generated.DeclarationOperation{{Sequence: 1, OperationID: draft.BindingID, OperationType: "gate.profile.bind", AdapterID: "core.gate", TargetID: draft.Scope.ProfileID, InputDigest: draft.ScopeDigest, ArtifactDigest: draft.ScopeDigest, Idempotent: true}},
		ReasonDigest: draft.ScopeDigest, Extensions: []generated.ContractExtension{},
	}
	raw, err := json.Marshal(request)
	if err != nil || generated.ValidateContractJSON(generated.SchemaIDDeclarationRevisionRequest, raw, generated.ContractExact) != nil {
		return generated.DeclarationRevisionRequest{}, errors.New("profile change contract invalid")
	}
	return request, nil
}
