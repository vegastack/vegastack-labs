package localapi

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/localtransport"
	"github.com/vegastack/vegastack-labs/internal/maintenance"
	"github.com/vegastack/vegastack-labs/internal/principal"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
)

func (c *client) DiagnoseMaintenance(ctx context.Context, p serverconfig.Profile, id string) (TypedResponse[generated.MaintenanceDiagnosis], error) {
	if !principal.ValidID(id) {
		return TypedResponse[generated.MaintenanceDiagnosis]{}, failure.New(generated.ErrorCodeInputInvalid, "host-id", false)
	}
	return requestTyped(c, ctx, p, requestSpec{localtransport.MethodGet, "/api/v1/maintenance/hosts/" + id, "api.v1.maintenance.diagnose", maxOperationResponseBodyBytes, operationTimeout, false}, nil, func(d generated.MaintenanceDiagnosis, r generated.RunResult) bool {
		return validGateData(d, generated.SchemaIDMaintenanceDiagnosis) && d.HostID == id && d.StateRevision == r.StateRevision && d.RecoveryEpoch == r.RecoveryEpoch && d.ExistingWorkloads == "unchanged" && (d.Status == "healthy" || d.NewAdmissionBlocked)
	})
}
func (c *client) DraftMaintenance(ctx context.Context, p serverconfig.Profile, q generated.MaintenanceDraftRequest) (TypedResponse[generated.DeclarationRevision], error) {
	if !validGateData(q, generated.SchemaIDMaintenanceDraftRequest) {
		return TypedResponse[generated.DeclarationRevision]{}, failure.New(generated.ErrorCodeInputInvalid, "maintenance-request", false)
	}
	return requestTyped(c, ctx, p, requestSpec{localtransport.MethodPost, "/api/v1/maintenance/drafts", "api.v1.maintenance.drafts.create", maxOperationResponseBodyBytes, operationTimeout, true}, q, func(d generated.DeclarationRevision, r generated.RunResult) bool {
		if !validGateData(d, generated.SchemaIDDeclarationRevision) || !maintenance.ValidateDeclaration(d) || d.Maintenance == nil || d.DeclarationID != q.DeclarationID || d.Revision != q.ExpectedRevision || d.Status != "draft" || d.StateRevision != q.ExpectedStateRevision+1 || d.StateRevision != r.StateRevision || d.RecoveryEpoch != q.RecoveryEpoch || d.RecoveryEpoch != r.RecoveryEpoch {
			return false
		}
		m := d.Maintenance
		if hostaction.Digest(m.Incident) != hostaction.Digest(q.Incident) || m.Action != q.Action || m.CanaryHostID != q.CanaryHostID || m.CanaryRunID != q.CanaryRunID || m.ReasonDigest != q.ReasonDigest || len(m.Targets) != len(q.TargetIDs) {
			return false
		}
		for i, t := range m.Targets {
			if t.HostID != q.TargetIDs[i] {
				return false
			}
		}
		return true
	})
}
func maintenanceRemoteArguments(s requestSpec) []string {
	switch s.command {
	case "api.v1.maintenance.diagnose":
		if id, ok := pathID(s.path, "/api/v1/maintenance/hosts/", ""); ok {
			return []string{"maintenance", "diagnose", "--host-id", id}
		}
	case "api.v1.maintenance.drafts.create":
		if s.path == "/api/v1/maintenance/drafts" {
			return []string{"maintenance", "draft"}
		}
	}
	return nil
}
