package serverconfig

import (
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"strings"
)

func FreezeCIJobBindings(input []generated.CiJobExecutionBinding) ([]generated.CiJobExecutionBinding, error) {
	invalid := func() ([]generated.CiJobExecutionBinding, error) {
		return nil, failure.New(generated.ErrorCodeInputInvalid, "ci-job", false)
	}
	if len(input) > 128 {
		return invalid()
	}
	out := append([]generated.CiJobExecutionBinding(nil), input...)
	ids := map[string]bool{}
	hosts := map[string]bool{}
	for _, b := range out {
		raw, _ := json.Marshal(b)
		if generated.ValidateContractJSON(generated.SchemaIDCiJobExecutionBinding, raw, generated.ContractExact) != nil || ids[b.BindingID] || hosts[b.HostID] || b.CallerUID > int64(^uint32(0)) || b.MaximumSeconds > 3600 || strings.TrimSpace(b.RunnerGroupName) != b.RunnerGroupName || strings.ContainsAny(b.RunnerGroupName, "\r\n\x00") || b.SSHReferenceID == b.RegistrationReferenceID || b.SSHReferenceID == b.ObserverReferenceID || b.RegistrationReferenceID == b.ObserverReferenceID {
			return invalid()
		}
		ids[b.BindingID] = true
		hosts[b.HostID] = true
	}
	return out, nil
}
