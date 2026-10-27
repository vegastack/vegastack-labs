package localapi

import (
	"context"
	"net/url"
	"strconv"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/localtransport"
	"github.com/vegastack/vegastack-labs/internal/principal"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
)

func (client *client) ListCIEnrollments(ctx context.Context, p serverconfig.Profile, after string, limit int) (TypedResponse[generated.CiEnrollmentList], error) {
	if (after != "" && !principal.ValidID(after)) || limit < 1 || limit > 100 {
		return TypedResponse[generated.CiEnrollmentList]{}, failure.New(generated.ErrorCodeInputInvalid, "ci-enrollment-query", false)
	}
	query := url.Values{"limit": {strconv.Itoa(limit)}}
	if after != "" {
		query.Set("after", after)
	}
	return requestTyped(client, ctx, p, requestSpec{localtransport.MethodGet, "/api/v1/ci/enrollments?" + query.Encode(), "api.v1.ci.enrollments.list", maxOperationResponseBodyBytes, operationTimeout, false}, nil, func(d generated.CiEnrollmentList, r generated.RunResult) bool {
		return validCiEnrollmentList(d, r, after, limit)
	})
}

func validCiEnrollmentList(d generated.CiEnrollmentList, r generated.RunResult, after string, limit int) bool {
	if !validGateData(d, generated.SchemaIDCiEnrollmentList) || d.StateRevision != r.StateRevision || d.RecoveryEpoch != r.RecoveryEpoch || len(d.Enrollments) > limit {
		return false
	}
	previous := after
	for _, record := range d.Enrollments {
		if !validGateData(record, generated.SchemaIDCiEnrollmentRecord) || record.Definition.EnrollmentID <= previous || record.StateRevision > d.StateRevision || record.RecoveryEpoch != d.RecoveryEpoch {
			return false
		}
		previous = record.Definition.EnrollmentID
	}
	return d.NextAfter == "" || (len(d.Enrollments) == limit && d.NextAfter == previous && principal.ValidID(d.NextAfter))
}

func (client *client) GetCIEnrollment(ctx context.Context, p serverconfig.Profile, id string) (TypedResponse[generated.CiEnrollmentRecord], error) {
	if !principal.ValidID(id) {
		return TypedResponse[generated.CiEnrollmentRecord]{}, failure.New(generated.ErrorCodeInputInvalid, "ci-enrollment-id", false)
	}
	return requestTyped(client, ctx, p, requestSpec{localtransport.MethodGet, "/api/v1/ci/enrollments/" + id, "api.v1.ci.enrollments.get", maxOperationResponseBodyBytes, operationTimeout, false}, nil, func(d generated.CiEnrollmentRecord, r generated.RunResult) bool {
		return validGateData(d, generated.SchemaIDCiEnrollmentRecord) && d.Definition.EnrollmentID == id && d.StateRevision == r.StateRevision && d.RecoveryEpoch == r.RecoveryEpoch
	})
}
func (client *client) DraftCIEnrollment(ctx context.Context, p serverconfig.Profile, input generated.CiEnrollmentDraftRequest) (TypedResponse[generated.DeclarationRevision], error) {
	if !validGateData(input, generated.SchemaIDCiEnrollmentDraftRequest) {
		return TypedResponse[generated.DeclarationRevision]{}, failure.New(generated.ErrorCodeInputInvalid, "ci-enrollment-request", false)
	}
	return requestTyped(client, ctx, p, requestSpec{localtransport.MethodPost, "/api/v1/ci/enrollments/drafts", "api.v1.ci.enrollments.drafts.create", maxOperationResponseBodyBytes, operationTimeout, true}, input, func(d generated.DeclarationRevision, r generated.RunResult) bool {
		if !validGateData(d, generated.SchemaIDDeclarationRevision) || d.CIEnrollment == nil || len(d.Operations) != 1 {
			return false
		}
		imported := d.CIEnrollment
		operation := d.Operations[0]
		digest := hostaction.Digest(imported)
		return validGateData(*imported, generated.SchemaIDCiEnrollmentRequest) && imported.Definition.EnrollmentID == input.EnrollmentID && imported.Definition.BindingID == input.BindingID && imported.ExpectedStateRevision == input.ExpectedStateRevision && imported.RecoveryEpoch == input.RecoveryEpoch && imported.IdempotencyKey == input.IdempotencyKey && imported.ReasonDigest == input.ReasonDigest && d.DeclarationID == "ci-enrollment-"+hostaction.Digest(input.EnrollmentID)[7:39] && d.DeclarationType == "ci.enrollment.register" && d.Status == "draft" && len(d.Extensions) == 0 && d.Revision == 1 && d.StateRevision == input.ExpectedStateRevision+1 && d.StateRevision == r.StateRevision && d.RecoveryEpoch == input.RecoveryEpoch && d.RecoveryEpoch == r.RecoveryEpoch && operation.Sequence == 1 && operation.OperationID == "ci-enrollment" && operation.OperationType == "ci.enrollment.register" && operation.AdapterID == "core.ci-enrollment" && operation.TargetID == input.EnrollmentID && operation.InputDigest == digest && operation.ArtifactDigest == digest && !operation.Idempotent && operation.OffsiteRunSpec == nil
	})
}

func ciEnrollmentRemoteArguments(spec requestSpec) []string {
	switch spec.command {
	case "api.v1.ci.enrollments.drafts.create":
		if spec.path == "/api/v1/ci/enrollments/drafts" {
			return []string{"ci", "enrollment", "draft"}
		}
	case "api.v1.ci.enrollments.get":
		if id, ok := pathID(spec.path, "/api/v1/ci/enrollments/", ""); ok {
			return []string{"ci", "enrollment", "show", "--enrollment-id", id}
		}
	case "api.v1.ci.enrollments.list":
		parsed, err := url.Parse(spec.path)
		if err != nil || parsed.Path != "/api/v1/ci/enrollments" || parsed.Fragment != "" || parsed.IsAbs() {
			return nil
		}
		query, err := url.ParseQuery(parsed.RawQuery)
		if err != nil {
			return nil
		}
		args := []string{"ci", "enrollment", "list"}
		for key, values := range query {
			if (key != "after" && key != "limit") || len(values) != 1 {
				return nil
			}
		}
		if v, ok := query["after"]; ok {
			if !principal.ValidID(v[0]) {
				return nil
			}
			args = append(args, "--after", v[0])
		}
		if v, ok := query["limit"]; ok {
			n, e := strconv.Atoi(v[0])
			if e != nil || n < 1 || n > 100 || strconv.Itoa(n) != v[0] {
				return nil
			}
			args = append(args, "--limit", v[0])
		}
		return args
	}
	return nil
}
