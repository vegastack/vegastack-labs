package hostinglifecycle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

const AdapterID = "hosting-lifecycle"
const Operation = "hosting.lifecycle.apply"
const OperationID = "hosting.lifecycle.apply.v1"

type Profile struct {
	Binding generated.HostingLifecycleProfile
}
type Outcome struct {
	Status, ResultDigest string
	OwnedResources       []generated.HostingOwnedResource
}

func Digest(v any) string {
	b, _ := json.Marshal(v)
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}
func ValidateRequest(in generated.HostingLifecycleRequest) error {
	b, _ := json.Marshal(in)
	return generated.ValidateContractJSON(generated.SchemaIDHostingLifecycleRequest, b, generated.ContractExact)
}
