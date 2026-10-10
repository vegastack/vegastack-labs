//go:build linux

package qualification

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strconv"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
)

// ExecuteStep reads only the fixed administrator-installed scope and exact
// artifact slot. Execution retains the normal server authorization and Slack
// approval route. Its output is diagnostic, never a native proof receipt.
func ExecuteStep(ctx context.Context, profile serverconfig.Profile, in generated.NativeStepRequest) (generated.NativeStepResult, error) {
	out := generated.NativeStepResult{Schema: generated.SchemaIDNativeStepResult, SchemaVersion: "1.0.0", Binding: in, Status: "failed", ObservationDigests: []string{}, ReceiptDigests: []string{}, ProducerRunIDs: []string{}}
	if ownedDirectory("/run/vsk-labs-native", 0) != nil {
		return out, ErrUnavailable
	}
	value, err := loadGuestScope(ctx)
	if err != nil {
		return out, err
	}
	scope, err := validateScope(value)
	if err != nil || validateStep(scope, in, time.Now().UTC()) != nil {
		return out, ErrUnavailable
	}
	localGuest := in.GuestID
	if in.Operation != "witness" && in.Operation != "select-controller" {
		localGuest = ""
		for id, g := range scope.guests {
			if (g.Role == "controller" || g.Role == "replacement") && verifyLocalGuest(g) == nil {
				if localGuest != "" {
					return out, ErrUnavailable
				}
				localGuest = id
			}
		}
	}
	if localGuest == "" || verifyLocalGuest(scope.guests[localGuest]) != nil {
		return out, ErrUnavailable
	}
	executable, err := fileDigest("/proc/self/exe", 256*1024*1024)
	if err != nil || executable != scope.value.ExecutableDigest {
		return out, ErrUnavailable
	}
	slot := filepath.Join("/run/vsk-labs-native", in.ScenarioID+"-"+strconv.FormatInt(in.Ordinal, 10)+".json")
	raw, err := ownedFile(slot, 0, 65536)
	var installed generated.NativeStepRequest
	if err != nil || generated.ValidateContractJSON(generated.SchemaIDNativeStepRequest, raw, generated.ContractExact) != nil || json.Unmarshal(raw, &installed) != nil || hostaction.Digest(installed) != hostaction.Digest(in) {
		return out, ErrUnavailable
	}
	deadline, _ := time.Parse(time.RFC3339, in.Deadline)
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	if in.Operation == "witness" || in.Operation == "select-controller" {
		return executeWitness(ctx, scope, in, out)
	}
	if in.Operation == "cleanup-native" {
		return out, ErrUnavailable
	}
	if in.Operation == "prepare" {
		return executePreparation(ctx, scope, in, out)
	}
	packet := nativeAPIPacket{Step: in, Kind: in.Operation}
	if in.Operation == "collect-native" {
		raw, e := ownedFile(filepath.Join("/run/vsk-labs-native", in.ScenarioID+"-"+strconv.FormatInt(in.Ordinal, 10)+".collect.json"), 0, 32768)
		var request generated.NativeCollectRequest
		if e != nil || !exactFixtureDecode(raw, generated.SchemaIDNativeCollectRequest, &request) {
			return out, ErrUnavailable
		}
		packet.Collection = &request
	}
	reply, e := callNativeAPI(ctx, scope, packet)
	if e != nil {
		return out, e
	}
	return reply.Result, nil
}
