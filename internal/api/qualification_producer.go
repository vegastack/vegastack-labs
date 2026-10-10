package api

import (
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"net/http"
)

func (app *Application) qualificationProducer(c QualificationOperations) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, _ authorization.ReadScope, _ map[string]string) {
		const op = "api.v1.qualification.producer"
		if !qualificationLocal(r) {
			app.failure(w, op, apiFailure(generated.ErrorCodeAuthorizationDenied, "operator-local"))
			return
		}
		var in generated.NativeProducerLookupRequest
		if decodeOperationRequest(r, 8192, []string{"schema", "schemaVersion", "scopeDigest", "scenarioId", "hostId", "planId", "planDigest", "runId", "stepId", "recoveryEpoch"}, &in) != nil {
			app.failure(w, op, apiFailure(generated.ErrorCodeInputInvalid, "native-producer"))
			return
		}
		raw, _ := json.Marshal(in)
		if generated.ValidateContractJSON(generated.SchemaIDNativeProducerLookupRequest, raw, generated.ContractExact) != nil {
			app.failure(w, op, apiFailure(generated.ErrorCodeInputInvalid, "native-producer"))
			return
		}
		for _, target := range []authorization.Target{{Capability: "run.read", ResourceKind: "run", ResourceID: in.RunID}, {Capability: "host.read", ResourceKind: "host", ResourceID: in.HostID}} {
			if _, err := app.authorizeAction(r, authorization.ActionRead, target); err != nil {
				app.failure(w, op, err)
				return
			}
		}
		out, err := c.Service.LookupNativeProducerData(r.Context(), in)
		if err != nil {
			app.failure(w, op, err)
			return
		}
		raw, _ = json.Marshal(out)
		ref := out.ProducerReference
		protocol := in.ScenarioID == "action-replay" || in.ScenarioID == "action-concurrency"
		if generated.ValidateContractJSON(generated.SchemaIDNativeProducerLookupData, raw, generated.ContractExact) != nil || ref.ScenarioID != in.ScenarioID || ref.HostID != in.HostID || ref.PlanID != in.PlanID || ref.PlanDigest != in.PlanDigest || ref.RunID != in.RunID || ref.StepID != in.StepID || protocol != (out.ActionBundle != nil) || out.ActionBundle != nil && !hostaction.NativeProducerBundleMatches(in, ref, *out.ActionBundle) {
			app.failure(w, op, apiFailure(generated.ErrorCodeIntegrityFailure, "native-producer-binding"))
			return
		}
		current, err := c.Revisions.CurrentRevision(r.Context())
		if err != nil {
			app.failure(w, op, err)
			return
		}
		if current.RecoveryEpoch != in.RecoveryEpoch {
			app.failure(w, op, apiFailure(generated.ErrorCodePrerequisiteBlocked, "native-producer-epoch"))
			return
		}
		app.success(w, op, current.StateRevision, current.RecoveryEpoch, out)
	}
}
