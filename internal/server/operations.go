package server

import (
	"context"
	"net/http"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localapi"
	"github.com/vegastack/vegastack-labs/internal/result"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
)

type Operations struct {
	build      result.BuildInfo
	requestIDs result.RequestIDSource
}

func NewOperations(build result.BuildInfo, requestIDs result.RequestIDSource) *Operations {
	return &Operations{build: build, requestIDs: requestIDs}
}

func (operations *Operations) Run(ctx context.Context, configPath string) error {
	probe := NewRuntimePlatformProbe()
	platform, err := probe.Current(ctx)
	if err != nil {
		return stableOr(err, generated.ErrorCodeUnsupportedPlatform, "server-platform")
	}
	if !supportedPlatform(platform) {
		return failure.New(generated.ErrorCodeUnsupportedPlatform, "server-platform", false)
	}
	ownerUID, err := currentServiceOwnerUID()
	if err != nil {
		return failure.New(generated.ErrorCodeUnsupportedPlatform, "server-platform", false)
	}
	profile, err := serverconfig.NewLoader(ownerUID).Load(ctx, configPath)
	if err != nil {
		return err
	}
	factory := result.NewFactory(operations.build, operations.requestIDs)
	service, err := New(Config{Profile: profile, Application: initialApplication{}, Results: factory, PlatformProbe: fixedPlatformProbe{platform: platform}})
	if err != nil {
		return err
	}
	return service.Run(ctx)
}

func (operations *Operations) Status(ctx context.Context, configPath string) (localapi.Response, error) {
	ownerUID, err := currentServiceOwnerUID()
	if err != nil {
		return localapi.Response{}, failure.New(generated.ErrorCodeUnsupportedPlatform, "server-platform", false)
	}
	profile, err := serverconfig.NewLoader(ownerUID).Load(ctx, configPath)
	if err != nil {
		return localapi.Response{}, err
	}
	return localapi.NewClient(result.NewFactory(operations.build, operations.requestIDs)).Status(ctx, profile)
}

type fixedPlatformProbe struct{ platform Platform }

func (probe fixedPlatformProbe) Current(context.Context) (Platform, error) {
	return probe.platform, nil
}

type initialApplication struct{}

func (initialApplication) Start(context.Context) error { return nil }
func (initialApplication) Health(context.Context) (ApplicationHealth, error) {
	return ApplicationHealth{}, nil
}
func (initialApplication) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	http.NotFound(writer, request)
}
func (initialApplication) Shutdown(context.Context) error { return nil }
