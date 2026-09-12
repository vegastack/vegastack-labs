package server

import (
	"context"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/result"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
)

func TestOperationsFailClosedOnUnsupportedRuntimeBeforeConfigRead(t *testing.T) {
	operations := NewOperations(result.BuildInfo{ToolVersion: "test", ReleaseBuildID: "test"}, func() (string, error) { return "request-test", nil })
	operations.platformProbe = fixedPlatformProbe{platform: Platform{OS: "unsupported", Architecture: "unsupported"}}
	err := operations.Run(context.Background(), "/private/config-canary-does-not-exist")
	stable, ok := failure.As(err)
	if !ok || stable.Code != generated.ErrorCodeUnsupportedPlatform {
		t.Fatalf("Run() error = %v", err)
	}
}

func TestOperationsRemoteReadIsDisabledOrFailsClosedBeforeServing(t *testing.T) {
	operations := NewOperations(result.BuildInfo{ToolVersion: "test", ReleaseBuildID: "test"}, func() (string, error) { return "request-test", nil })
	factory := result.NewFactory(operations.build, operations.requestIDs)
	if remote, sessions := operations.remoteRead(context.Background(), serverconfig.Profile{}, nil, factory); remote != nil || sessions != nil {
		t.Fatalf("disabled remote = %#v, %#v", remote, sessions)
	}
	invalid := serverconfig.Profile{RemoteRead: serverconfig.RemoteRead{Enabled: true}}
	remote, sessions := operations.remoteRead(context.Background(), invalid, nil, factory)
	if remote == nil || remote.PreflightFailure != RemoteReadReasonPreflightUnavailable || sessions != nil {
		t.Fatalf("invalid remote = %#v, %#v", remote, sessions)
	}
	profile := serverconfig.Profile{RemoteRead: serverconfig.RemoteRead{Enabled: true, ConfigurationValid: true, IdentityConfigPath: "/private/missing-cloudflare-profile"}}
	remote, sessions = operations.remoteRead(context.Background(), profile, nil, factory)
	if remote == nil || remote.PreflightFailure != RemoteReadReasonAuthenticationFailed || sessions != nil {
		t.Fatalf("failed remote = %#v, %#v", remote, sessions)
	}
}
