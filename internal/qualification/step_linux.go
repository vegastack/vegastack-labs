//go:build linux

package qualification

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/localapi"
	"github.com/vegastack/vegastack-labs/internal/result"
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
	if in.Operation != "witness" {
		for id, g := range scope.guests {
			if g.Role == "controller" {
				localGuest = id
			}
		}
	}
	if verifyLocalGuest(scope.guests[localGuest]) != nil {
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
	if in.Operation == "witness" {
		return executeWitness(ctx, scope, in, out)
	}
	if in.Operation == "cleanup-native" {
		return out, ErrUnavailable
	}
	revision := scope.value.SourceCommit
	client := localapi.NewClient(result.NewFactory(result.BuildInfo{ToolVersion: "native-qualification", ReleaseBuildID: scope.value.ExecutableDigest, SourceRevision: &revision}, func() (string, error) { return strings.TrimPrefix(in.Nonce, "sha256:"), nil }))
	if in.Operation == "collect-native" {
		raw, e := ownedFile(filepath.Join("/run/vsk-labs-native", in.ScenarioID+"-"+strconv.FormatInt(in.Ordinal, 10)+".collect.json"), 0, 32768)
		var request generated.NativeCollectRequest
		if e != nil || generated.ValidateContractJSON(generated.SchemaIDNativeCollectRequest, raw, generated.ContractExact) != nil || json.Unmarshal(raw, &request) != nil || request.ScopeDigest != scope.digest || request.ProfileID != scope.value.ProfileID || request.RecoveryEpoch != in.RecoveryEpoch {
			return out, ErrUnavailable
		}
		allowed := map[string]bool{}
		for _, scenario := range StageScenarios(request.Stage) {
			allowed[scenario] = true
		}
		if !allowed[in.ScenarioID] {
			return out, ErrUnavailable
		}
		for _, producer := range request.Producers {
			if !allowed[producer.ScenarioID] {
				return out, ErrUnavailable
			}
		}
		response, e := client.CollectNativeQualification(ctx, profile, request)
		if e != nil {
			return out, e
		}
		if response.ExitCode != 0 {
			return out, ErrUnavailable
		}
		out.Changed = response.Result.Changed
		out.Collection = &response.Data
		out.Status = "completed"
		return out, nil
	}
	if in.Operation == "execute" {
		response, err := client.ApplyBound(ctx, profile, generated.PlanReferenceRequest{Schema: generated.SchemaIDPlanReferenceRequest, SchemaVersion: "1.0.0", PlanID: in.PlanID, PlanDigest: in.PlanDigest, RecoveryEpoch: in.RecoveryEpoch, IdempotencyKey: strings.TrimPrefix(in.Nonce, "sha256:"), Extensions: []generated.ContractExtension{}})
		if err != nil {
			return out, err
		}
		if response.ExitCode != 0 {
			return out, ErrUnavailable
		}
		out.Changed = response.Result.Changed
		out.ProducerRunIDs = []string{response.Data.Run.RunID}
		out.Status = "awaiting-fixture"
		return out, nil
	}
	response, err := client.InspectRun(ctx, profile, in.RunID)
	if err != nil {
		return out, err
	}
	run := response.Data.Run
	if response.ExitCode != 0 || run.RunID != in.RunID || run.PlanID != in.PlanID || run.PlanDigest != in.PlanDigest || run.RecoveryEpoch != in.RecoveryEpoch {
		return out, ErrUnavailable
	}
	found := false
	for _, step := range run.Steps {
		if step.StepID == in.StepID {
			found = true
		}
	}
	if !found {
		return out, ErrUnavailable
	}
	out.ProducerRunIDs = []string{run.RunID}
	// The collector independently joins the actual execution lease and receipts.
	// A public run projection cannot establish either one.
	out.Status = "awaiting-fixture"
	return out, nil
}
