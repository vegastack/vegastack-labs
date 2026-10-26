package localapi

import (
	"context"
	"net/url"
	"strconv"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localtransport"
	"github.com/vegastack/vegastack-labs/internal/principal"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/servicecatalog"
)

func (client *client) ListServices(ctx context.Context, p serverconfig.Profile, after string, limit int) (TypedResponse[generated.ServiceList], error) {
	if (after != "" && !principal.ValidID(after)) || limit < 1 || limit > 100 {
		return TypedResponse[generated.ServiceList]{}, failure.New(generated.ErrorCodeInputInvalid, "service-query", false)
	}
	query := url.Values{"limit": {strconv.Itoa(limit)}}
	if after != "" {
		query.Set("after", after)
	}
	return requestTyped(client, ctx, p, requestSpec{localtransport.MethodGet, "/api/v1/services?" + query.Encode(), "api.v1.services.list", maxOperationResponseBodyBytes, operationTimeout, false}, nil, func(d generated.ServiceList, r generated.RunResult) bool { return validServiceList(d, r, after, limit) })
}

func validServiceList(d generated.ServiceList, r generated.RunResult, after string, limit int) bool {
	if !validGateData(d, generated.SchemaIDServiceList) || d.StateRevision != r.StateRevision || d.RecoveryEpoch != r.RecoveryEpoch || len(d.Services) > limit {
		return false
	}
	previous := after
	for _, record := range d.Services {
		if !validGateData(record, generated.SchemaIDServiceRecord) || record.Definition.ServiceID <= previous || record.StateRevision > d.StateRevision || record.RecoveryEpoch != d.RecoveryEpoch {
			return false
		}
		previous = record.Definition.ServiceID
	}
	return d.NextAfter == "" || (len(d.Services) == limit && d.NextAfter == previous && principal.ValidID(d.NextAfter))
}

func (client *client) GetService(ctx context.Context, p serverconfig.Profile, id string) (TypedResponse[generated.ServiceRecord], error) {
	if !principal.ValidID(id) {
		return TypedResponse[generated.ServiceRecord]{}, failure.New(generated.ErrorCodeInputInvalid, "service-id", false)
	}
	return requestTyped(client, ctx, p, requestSpec{localtransport.MethodGet, "/api/v1/services/" + id, "api.v1.services.get", maxOperationResponseBodyBytes, operationTimeout, false}, nil, func(d generated.ServiceRecord, r generated.RunResult) bool {
		return validGateData(d, generated.SchemaIDServiceRecord) && d.Definition.ServiceID == id && d.StateRevision == r.StateRevision && d.RecoveryEpoch == r.RecoveryEpoch
	})
}
func (client *client) ObserveService(ctx context.Context, p serverconfig.Profile, id string) (TypedResponse[generated.ServiceObservation], error) {
	if !principal.ValidID(id) {
		return TypedResponse[generated.ServiceObservation]{}, failure.New(generated.ErrorCodeInputInvalid, "service-id", false)
	}
	return requestTyped(client, ctx, p, requestSpec{localtransport.MethodGet, "/api/v1/services/" + id + "/observation", "api.v1.services.observation.get", maxOperationResponseBodyBytes, operationTimeout, false}, nil, func(d generated.ServiceObservation, r generated.RunResult) bool {
		return validGateData(d, generated.SchemaIDServiceObservation) && d.ServiceID == id && d.StateRevision == r.StateRevision && d.RecoveryEpoch == r.RecoveryEpoch
	})
}
func (client *client) DraftServiceImport(ctx context.Context, p serverconfig.Profile, input generated.ServiceImportDraftRequest) (TypedResponse[generated.DeclarationRevision], error) {
	if !validGateData(input, generated.SchemaIDServiceImportDraftRequest) {
		return TypedResponse[generated.DeclarationRevision]{}, failure.New(generated.ErrorCodeInputInvalid, "service-request", false)
	}
	return requestTyped(client, ctx, p, requestSpec{localtransport.MethodPost, "/api/v1/services/import-drafts", "api.v1.services.import-drafts.create", maxOperationResponseBodyBytes, operationTimeout, true}, input, func(d generated.DeclarationRevision, r generated.RunResult) bool {
		if !validGateData(d, generated.SchemaIDDeclarationRevision) || d.ServiceImport == nil || len(d.Operations) != 1 {
			return false
		}
		imported := d.ServiceImport
		operation := d.Operations[0]
		digest := servicecatalog.Digest(imported)
		return servicecatalog.ValidateImportRequest(*imported) == nil && imported.Definition.ServiceID == input.ServiceID && imported.Definition.BindingID == input.BindingID && imported.ExpectedStateRevision == input.ExpectedStateRevision && imported.RecoveryEpoch == input.RecoveryEpoch && imported.IdempotencyKey == input.IdempotencyKey && imported.ReasonDigest == input.ReasonDigest && d.DeclarationID == "service-import-"+servicecatalog.Digest(input.ServiceID)[7:39] && d.DeclarationType == servicecatalog.Operation && d.Status == "draft" && len(d.Extensions) == 0 && d.Revision == 1 && d.StateRevision == input.ExpectedStateRevision+1 && d.StateRevision == r.StateRevision && d.RecoveryEpoch == input.RecoveryEpoch && d.RecoveryEpoch == r.RecoveryEpoch && operation.Sequence == 1 && operation.OperationID == servicecatalog.OperationID && operation.OperationType == servicecatalog.Operation && operation.AdapterID == servicecatalog.AdapterID && operation.TargetID == input.ServiceID && operation.InputDigest == digest && operation.ArtifactDigest == digest && !operation.Idempotent && operation.OffsiteRunSpec == nil
	})
}

func serviceRemoteArguments(spec requestSpec) []string {
	switch spec.command {
	case "api.v1.services.import-drafts.create":
		if spec.path == "/api/v1/services/import-drafts" {
			return []string{"service", "import", "draft"}
		}
	case "api.v1.services.get", "api.v1.services.observation.get":
		action, suffix := "show", ""
		if spec.command == "api.v1.services.observation.get" {
			action, suffix = "observe", "/observation"
		}
		if id, ok := pathID(spec.path, "/api/v1/services/", suffix); ok {
			return []string{"service", action, "--service-id", id}
		}
	case "api.v1.services.list":
		parsed, err := url.Parse(spec.path)
		if err != nil || parsed.Path != "/api/v1/services" || parsed.Fragment != "" || parsed.IsAbs() {
			return nil
		}
		query, err := url.ParseQuery(parsed.RawQuery)
		if err != nil {
			return nil
		}
		args := []string{"service", "list"}
		for key, values := range query {
			if (key != "after" && key != "limit") || len(values) != 1 {
				return nil
			}
		}
		if values, ok := query["after"]; ok {
			if !principal.ValidID(values[0]) {
				return nil
			}
			args = append(args, "--after", values[0])
		}
		if values, ok := query["limit"]; ok {
			limit, err := strconv.Atoi(values[0])
			if err != nil || limit < 1 || limit > 100 || strconv.Itoa(limit) != values[0] {
				return nil
			}
			args = append(args, "--limit", values[0])
		}
		return args
	}
	return nil
}
