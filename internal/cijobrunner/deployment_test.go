package cijobrunner

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter/coolify"
	"github.com/vegastack/vegastack-labs/internal/cijobguard"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
)

func deploymentFixture() DeploymentCommand {
	return DeploymentCommand{PlanID: "plan-deploy", PlanDigest: hostaction.Digest("plan"), RunID: "run-deploy", StepID: "step-deploy", LeaseID: "lease-deploy", LeaseDigest: hostaction.Digest("lease"), ReferenceID: "app-deploy", MaterialVersion: "version-one", Deadline: time.Now().Add(time.Minute), Origin: "https://coolify.example/api/v1", Digest: hostaction.Digest("image")}
}
func TestDeploymentPrivateSessionRequiresReadyExactChecksAndOneDelivery(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	_ = a.SetDeadline(time.Now().Add(3 * time.Second))
	_ = b.SetDeadline(time.Now().Add(3 * time.Second))
	worker := NewStream(a, a)
	worker.configured = true
	controller := NewControl(b, b)
	controller.configuredOK = true
	command := deploymentFixture()
	secret, _ := credentialref.NewValue([]byte("private-synthetic-320"))
	defer secret.Close()
	if controller.WriteDeployment(ctx, command, secret) == nil {
		t.Fatal("unqualified early secret delivery")
	}
	var consumed *credentialref.Value
	worker.deploymentConsumer = func(ctx context.Context, c DeploymentCommand, v *credentialref.Value, check func(context.Context) error) (DeploymentResult, error) {
		consumed = v
		if c.PlanID != command.PlanID || string(v.Bytes()) != "private-synthetic-320" {
			t.Error("changed handoff")
		}
		if e := check(ctx); e != nil {
			return DeploymentResult{}, e
		}
		return DeploymentResult{CommandDigest: hostaction.Digest(c), Succeeded: true, Receipt: coolify.DeploymentReceipt{ApplicationUUID: "application-one", Stage: "queued"}}, nil
	}
	done := make(chan error, 1)
	go func() { _, e := worker.Held(ctx); done <- e }()
	if m, e := controller.Receive(ctx); e != nil || m.Kind != "held" {
		t.Fatal(m, e)
	}
	if e := controller.WriteDeploymentOffer(ctx, command); e != nil {
		t.Fatal(e)
	}
	if m, e := controller.Receive(ctx); e != nil || m.Kind != "deployment-ready" {
		t.Fatal(m, e)
	}
	if e := controller.WriteDeployment(ctx, command, secret); e != nil {
		t.Fatal(e)
	}
	if controller.WriteDeployment(ctx, command, secret) == nil {
		t.Fatal("replayed credential")
	}
	m, e := controller.Receive(ctx)
	if e != nil || m.Kind != "deployment-check" {
		t.Fatal(m, e)
	}
	if e = controller.WriteDeploymentChecked(ctx, *m.DeploymentCheck); e != nil {
		t.Fatal(e)
	}
	m, e = controller.Receive(ctx)
	if e != nil || m.Kind != "deployment-result" || !m.DeploymentResult.Succeeded {
		t.Fatal(m, e)
	}
	if e = controller.WriteDecision(ctx, cijobguard.Decision{Action: "allow"}); e != nil {
		t.Fatal(e)
	}
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	if consumed == nil || len(consumed.Bytes()) != 0 {
		t.Fatal("borrowed worker value not closed")
	}
	if controller.WriteDeploymentChecked(ctx, DeploymentCheck{CommandDigest: hostaction.Digest(command), Sequence: 1}) == nil {
		t.Fatal("check accepted after result")
	}
}
func TestDeploymentRejectsMixedAndSecretBearingResultFrames(t *testing.T) {
	for _, raw := range []string{
		`{"kind":"deployment-result","token":"c2VjcmV0","deploymentResult":{"commandDigest":"x","receipt":{},"succeeded":true}}`,
		`{"kind":"deployment","token":"c2VjcmV0"}`,
		`{"kind":"deployment-ready","deploymentCheck":{"commandDigest":"x","sequence":0},"extra":"secret"}`,
	} {
		var f frame
		if decodeFrame(context.Background(), []byte(raw), &f) == nil {
			t.Fatal("invalid private message accepted")
		}
	}
	if validDeployment(DeploymentCommand{PlanID: strings.Repeat("a", 200)}) {
		t.Fatal("unbounded command")
	}
}
