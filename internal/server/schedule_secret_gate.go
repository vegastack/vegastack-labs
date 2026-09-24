package server

import (
	"context"
	"errors"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
	runengine "github.com/vegastack/vegastack-labs/internal/run"
)

type scheduledBackupLiveGate struct {
	admission scheduleAdmission
	fallback  runengine.GateVerifier
	clock     func() time.Time
}

func (gate scheduledBackupLiveGate) VerifySecretStep(ctx context.Context, plan generated.Plan, operation generated.PlanOperation) error {
	if operation.AdapterID != "local.backup" || (operation.OperationType != "backup.local.create" && operation.OperationType != "backup.local.verify") {
		if gate.fallback == nil {
			return errors.New("secret gate unavailable")
		}
		return gate.fallback.VerifySecretStep(ctx, plan, operation)
	}
	policy, occurrence, credentials, backup := false, false, false, false
	for _, extension := range plan.Extensions {
		switch extension.Name {
		case "x-scheduled-policy":
			policy = extension.ValueDigest != ""
		case "x-scheduled-occurrence":
			occurrence = extension.ValueDigest != ""
		case "x-scheduled-credential-bindings":
			credentials = extension.ValueDigest != ""
		case "x-backup-policy":
			backup = extension.ValueDigest != ""
		}
	}
	if !policy || !occurrence || !credentials || !backup || plan.AuthorizationBranch != "preauthorized" || plan.ExecutorMode != "central" {
		return errors.New("scheduled backup live gate binding invalid")
	}
	clock := gate.clock
	if clock == nil {
		clock = time.Now
	}
	return gate.admission.ValidateScheduledPlan(ctx, plan, clock().UTC().Truncate(time.Second))
}
