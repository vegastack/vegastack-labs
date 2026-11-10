package hostinglifecycle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	if err := generated.ValidateContractJSON(generated.SchemaIDHostingLifecycleRequest, b, generated.ContractExact); err != nil {
		return err
	}
	return ValidateRecovery(in.RecoveryRunID, in.RecoveryRecordDigest, in.RecoveryResources)
}

// A recovery selection is inert until its complete proof is sealed into a new plan.
func ValidateRecovery(runID, recordDigest string, resources []generated.HostingOwnedResource) error {
	if runID == "" && recordDigest == "" && len(resources) == 0 {
		return nil
	}
	if runID == "" || recordDigest == "" || len(resources) == 0 {
		return errors.New("incomplete hosting recovery proof")
	}
	seen := map[string]bool{}
	for _, r := range resources {
		key := r.Kind + "\x00" + r.ParentID
		if seen[key] {
			return errors.New("duplicate hosting recovery resource")
		}
		seen[key] = true
	}
	return nil
}
