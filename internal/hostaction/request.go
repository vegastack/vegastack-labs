package hostaction

import (
	"context"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/strictjson"
)

const AdapterID = "host-action"
const PurposeID = "host-action-ssh"
const OperationType = "host.action.execute"

func ValidateRequest(r generated.HostActionRequest) error {
	raw, err := json.Marshal(r)
	if err != nil || len(raw) > MaximumEnvelope || generated.ValidateContractJSON(generated.SchemaIDHostActionRequest, raw, generated.ContractExact) != nil || r.CallerUID > int64(^uint32(0)) || r.ActionInputDigest != BytesDigest([]byte(r.ActionInput)) || strictjson.Scan(context.Background(), []byte(r.ActionInput), strictjson.Limits{MaxDepth: 16}) != nil || r.ConsoleConfirmation.TargetDigest != r.TargetDigest {
		return blocked()
	}
	return nil
}
func DraftID(r generated.HostActionRequest) string { return "host-action-" + Digest(r)[7:39] }
