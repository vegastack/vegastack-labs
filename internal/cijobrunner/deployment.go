package cijobrunner

import (
	"context"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter/coolify"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
)

// DeploymentCommand is server-selected non-secret configuration for one external
// lease. The credential travels only in the existing private session's token field.
type DeploymentCommand struct {
	PlanID          string                    `json:"planId"`
	PlanDigest      string                    `json:"planDigest"`
	RunID           string                    `json:"runId"`
	StepID          string                    `json:"stepId"`
	LeaseID         string                    `json:"leaseId"`
	LeaseDigest     string                    `json:"leaseDigest"`
	ReferenceID     string                    `json:"referenceId"`
	MaterialVersion string                    `json:"materialVersion"`
	Epoch           uint64                    `json:"epoch"`
	Deadline        time.Time                 `json:"deadline"`
	Origin          string                    `json:"origin"`
	Target          coolify.ApplicationTarget `json:"target"`
	DestinationUUID string                    `json:"destinationUuid"`
	ServerUUID      string                    `json:"serverUuid"`
	ServerID        int64                     `json:"serverId"`
	Repository      string                    `json:"repository"`
	Digest          string                    `json:"digest"`
}
type DeploymentCheck struct {
	CommandDigest string `json:"commandDigest"`
	Sequence      uint32 `json:"sequence"`
}
type DeploymentResult struct {
	CommandDigest string                    `json:"commandDigest"`
	Receipt       coolify.DeploymentReceipt `json:"receipt"`
	Succeeded     bool                      `json:"succeeded"`
}

func validDeployment(c DeploymentCommand) bool {
	return identifier.MatchString(c.PlanID) && digest.MatchString(c.PlanDigest) && identifier.MatchString(c.RunID) && identifier.MatchString(c.StepID) && identifier.MatchString(c.LeaseID) && digest.MatchString(c.LeaseDigest) && identifier.MatchString(c.ReferenceID) && identifier.MatchString(c.MaterialVersion) && digest.MatchString(c.Digest) && c.Deadline.After(time.Now()) && c.Deadline.Before(time.Now().Add(time.Hour))
}
func consumeDeployment(ctx context.Context, c DeploymentCommand, v *credentialref.Value, check func(context.Context) error) (DeploymentResult, error) {
	result := DeploymentResult{CommandDigest: hostaction.Digest(c)}
	if !validDeployment(c) || v == nil || check == nil {
		return result, ErrBlocked
	}
	ctx, cancel := context.WithDeadline(ctx, c.Deadline)
	defer cancel()
	if e := check(ctx); e != nil {
		return result, e
	}
	client, e := coolify.NewClient(c.Origin, nil)
	if e != nil {
		return result, ErrBlocked
	}
	result.Receipt, e = client.DeployImage(ctx, coolify.ImageDeploymentRequest{Target: c.Target, DestinationUUID: c.DestinationUUID, ServerUUID: c.ServerUUID, ServerID: c.ServerID, Repository: c.Repository, Digest: c.Digest, Check: func() error { return check(ctx) }}, v)
	result.Succeeded = e == nil
	if e != nil {
		return result, ErrBlocked
	}
	return result, nil
}

func (s *Stream) deploymentCheck(ctx context.Context, command string, sequence uint32) error {
	if sequence == 0 || sequence > 32 {
		return ErrProtocol
	}
	if e := s.write(ctx, frame{Kind: "deployment-check", DeploymentCheck: &DeploymentCheck{CommandDigest: command, Sequence: sequence}}); e != nil {
		return e
	}
	reply, e := s.read(ctx)
	if e != nil || reply.Kind != "deployment-checked" || reply.DeploymentCheck == nil || reply.DeploymentCheck.CommandDigest != command || reply.DeploymentCheck.Sequence != sequence {
		return ErrBlocked
	}
	return nil
}
func (s *Stream) handleDeployment(ctx context.Context, f frame) error {
	if f.Deployment == nil || !validDeployment(*f.Deployment) || len(f.Token) == 0 {
		return ErrProtocol
	}
	defer clear(f.Token)
	value, e := credentialref.NewValue(f.Token)
	if e != nil {
		return ErrProtocol
	}
	defer value.Close()
	sequence := uint32(0)
	check := func(ctx context.Context) error {
		sequence++
		return s.deploymentCheck(ctx, hostaction.Digest(*f.Deployment), sequence)
	}
	consumer := s.deploymentConsumer
	if consumer == nil {
		consumer = consumeDeployment
	}
	result, e := consumer(ctx, *f.Deployment, value, check)
	if result.CommandDigest != hostaction.Digest(*f.Deployment) {
		return ErrProtocol
	}
	if e != nil {
		result.Succeeded = false
	}
	if s.write(ctx, frame{Kind: "deployment-result", DeploymentResult: &result}) != nil {
		return ErrProtocol
	}
	if e != nil {
		return ErrBlocked
	}
	return nil
}
func (c *Control) WriteDeployment(ctx context.Context, command DeploymentCommand, value *credentialref.Value) error {
	if !c.held || c.decided || c.deploymentSent || !c.deploymentReady || c.deploymentDigest != hostaction.Digest(command) || !validDeployment(command) || value == nil || len(value.Bytes()) == 0 {
		return ErrProtocol
	}
	c.deploymentSent = true
	return c.stream.write(ctx, frame{Kind: "deployment", Deployment: &command, Token: value.Bytes()})
}
func (c *Control) WriteDeploymentChecked(ctx context.Context, check DeploymentCheck) error {
	if check.CommandDigest != c.deploymentDigest || check.Sequence != c.deploymentSequence || check.Sequence == 0 || c.deploymentResult {
		return ErrProtocol
	}
	return c.stream.write(ctx, frame{Kind: "deployment-checked", DeploymentCheck: &check})
}

func (c *Control) WriteDeploymentOffer(ctx context.Context, command DeploymentCommand) error {
	if !c.held || c.decided || c.deploymentDigest != "" || !validDeployment(command) {
		return ErrProtocol
	}
	c.deploymentDigest = hostaction.Digest(command)
	return c.stream.write(ctx, frame{Kind: "deployment-offer", Deployment: &command})
}

// relayDeployment keeps the credential on the existing controller/PID1 private
// pipes. The host-side worker never runs the provider adapter itself.
func relayDeployment(ctx context.Context, inner *Stream, c DeploymentCommand, v *credentialref.Value, check func(context.Context) error) (DeploymentResult, error) {
	result := DeploymentResult{CommandDigest: hostaction.Digest(c)}
	if inner.write(ctx, frame{Kind: "deployment", Deployment: &c, Token: v.Bytes()}) != nil {
		return result, ErrProtocol
	}
	sequence := uint32(0)
	for {
		f, e := inner.read(ctx)
		if e != nil {
			return result, e
		}
		switch f.Kind {
		case "deployment-check":
			sequence++
			if f.DeploymentCheck == nil || f.DeploymentCheck.CommandDigest != result.CommandDigest || f.DeploymentCheck.Sequence != sequence || sequence > 32 {
				return result, ErrProtocol
			}
			if check(ctx) != nil {
				return result, ErrBlocked
			}
			if inner.write(ctx, frame{Kind: "deployment-checked", DeploymentCheck: f.DeploymentCheck}) != nil {
				return result, ErrProtocol
			}
		case "deployment-result":
			if f.DeploymentResult == nil || f.DeploymentResult.CommandDigest != result.CommandDigest {
				return result, ErrProtocol
			}
			return *f.DeploymentResult, nil
		default:
			return result, ErrProtocol
		}
	}
}
