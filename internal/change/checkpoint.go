package change

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/store"
)

func BuildCheckpointChange(chain audit.ChainRange, expected store.RevisionToken) (generated.DeclarationRevisionRequest, error) {
	if len(chain.Links) == 0 || chain.FirstEventID <= 0 || chain.LastEventID < chain.FirstEventID || !audit.ValidFingerprint(chain.RangeDigest) || chain.Links[0].RecoveryEpoch != expected.RecoveryEpoch || chain.Links[len(chain.Links)-1].RecoveryEpoch != expected.RecoveryEpoch || chain.Links[0].InstanceID == "" {
		return generated.DeclarationRevisionRequest{}, errors.New("audit checkpoint range is not current")
	}
	short := strings.TrimPrefix(string(chain.RangeDigest), "sha256:")[:24]
	request := generated.DeclarationRevisionRequest{
		Schema: generated.SchemaIDDeclarationRevisionRequest, SchemaVersion: "1.0.0",
		DeclarationID: "audit-checkpoint-" + short, DeclarationType: "audit-checkpoint",
		ExpectedRevision: 1, ExpectedStateRevision: expected.StateRevision, RecoveryEpoch: expected.RecoveryEpoch,
		Operations:   []generated.DeclarationOperation{{Sequence: 1, OperationID: "checkpoint-" + short, OperationType: "audit.checkpoint.anchor", AdapterID: "core.audit", TargetID: chain.Links[0].InstanceID, InputDigest: string(chain.RangeDigest), ArtifactDigest: string(chain.RangeDigest), Idempotent: true}},
		ReasonDigest: string(chain.RangeDigest), Extensions: []generated.ContractExtension{{Name: "x-audit-checkpoint", ValueDigest: string(chain.RangeDigest)}},
	}
	raw, err := json.Marshal(request)
	if err != nil || generated.ValidateContractJSON(generated.SchemaIDDeclarationRevisionRequest, raw, generated.ContractExact) != nil {
		return generated.DeclarationRevisionRequest{}, errors.New("audit checkpoint change contract invalid")
	}
	return request, nil
}
