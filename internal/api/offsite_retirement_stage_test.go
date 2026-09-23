package api

import (
	"context"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type localOffsiteSelectionFixture struct{ value store.LocalRetirementIntent }

func (f localOffsiteSelectionFixture) GetLocalRetirementIntentBySelection(context.Context, string) (store.LocalRetirementIntent, error) {
	return f.value, nil
}

type offsiteStagerFixture struct{}

func (offsiteStagerFixture) StageOffsiteRetirement(context.Context, store.OffsiteRetirementIntent) (string, error) {
	return "unexpected", nil
}

func TestOffsiteRetirementStageFailsClosedWithoutQualifiedCatalog(t *testing.T) {
	d := "sha256:" + strings.Repeat("a", 64)
	local := store.LocalRetirementIntent{Request: store.LocalRetirementStageRequest{SelectionDigest: d, StateRevision: 7, RecoveryEpoch: 2, Targets: []store.LocalRetirementTarget{{PointID: "point-old"}}, Survivors: []store.LocalRetirementSurvivor{{PointID: "point-good"}}}}
	service, err := NewOffsiteRetirementStageService(localOffsiteSelectionFixture{local}, offsiteStagerFixture{}, UnavailableOffsiteRetirementCatalogSource{})
	if err != nil {
		t.Fatal(err)
	}
	input := generated.BackupOffsiteRetirementStageRequest{Schema: generated.SchemaIDBackupOffsiteRetirementStageRequest, SchemaVersion: "1.1.0", ExpectedStateRevision: 7, RecoveryEpoch: 2, TargetDigest: d, IdempotencyKey: "key-test", SelectionDigest: d, PlanID: "plan-a", PlanDigest: d, OneOwnerProofID: "proof-a", LockAdminConsumerID: "lock-admin", RetentionConsumerID: "retention"}
	_, err = service.Stage(context.Background(), input, identity.Principal{ID: "human-a", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman})
	if apiErrorCode(err) != generated.ErrorCodePrerequisiteBlocked {
		t.Fatalf("error=%v", err)
	}
}
