//go:build linux

package qualification

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localapi"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
)

type fixturePlanHealthClient struct {
	localapi.Client
	plan        localapi.TypedResponse[generated.Plan]
	health      localapi.Response
	planErr     error
	healthErr   error
	healthRead  bool
	summaryRead bool
}

func (c *fixturePlanHealthClient) GetPlan(context.Context, serverconfig.Profile, string) (localapi.TypedResponse[generated.Plan], error) {
	return c.plan, c.planErr
}

func (c *fixturePlanHealthClient) Status(context.Context, serverconfig.Profile) (localapi.Response, error) {
	c.healthRead = true
	return c.health, c.healthErr
}

func (c *fixturePlanHealthClient) Summary(context.Context, serverconfig.Profile) (localapi.TypedResponse[generated.ApiSummaryData], error) {
	c.summaryRead = true
	// The fixture's initial grants permit control.health.read, not the
	// broader platform.summary.read capability.
	return localapi.TypedResponse[generated.ApiSummaryData]{ExitCode: 2}, nil
}

func TestNativeFixturePlanUsesGrantedHealthRead(t *testing.T) {
	step, plan, _ := nativePlanEnvelopeFixture(t)
	step.Operation = "prepare"
	packet := nativeAPIPacket{Kind: "fixture-plan", Step: step, Preparation: &generated.NativePreparationRequest{Kind: "fixture-approval", FixtureApproval: &generated.NativeSlackFixtureApproval{PlanID: plan.Data.PlanID}}}
	newClient := func() *fixturePlanHealthClient {
		return &fixturePlanHealthClient{plan: plan, health: localapi.Response{Result: generated.RunResult{StateRevision: plan.Data.Binding.StateRevision, RecoveryEpoch: step.RecoveryEpoch}}}
	}
	t.Run("minimal-bootstrap-grants", func(t *testing.T) {
		client := newClient()
		reply, err := dispatchNativeAPI(context.Background(), packet, client, serverconfig.Profile{})
		if err != nil || !client.healthRead || client.summaryRead || reply.Plan == nil || !reflect.DeepEqual(*reply.Plan, plan.Data) {
			t.Fatal("fixture approval could not use its granted health read", err)
		}
	})
	for name, change := range map[string]func(*fixturePlanHealthClient){
		"stale-state":    func(c *fixturePlanHealthClient) { c.health.Result.StateRevision++ },
		"wrong-epoch":    func(c *fixturePlanHealthClient) { c.health.Result.RecoveryEpoch++ },
		"health-failure": func(c *fixturePlanHealthClient) { c.health.ExitCode = 2 },
		"health-error":   func(c *fixturePlanHealthClient) { c.healthErr = errors.New("unavailable") },
		"plan-failure":   func(c *fixturePlanHealthClient) { c.plan.ExitCode = 2 },
		"plan-error":     func(c *fixturePlanHealthClient) { c.planErr = errors.New("unavailable") },
	} {
		t.Run(name, func(t *testing.T) {
			client := newClient()
			change(client)
			reply, err := dispatchNativeAPI(context.Background(), packet, client, serverconfig.Profile{})
			if !errors.Is(err, ErrUnavailable) || reply.Plan != nil || client.summaryRead {
				t.Fatal("invalid current authority released fixture plan", err)
			}
		})
	}
}
