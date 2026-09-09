package server

import (
	"context"

	"github.com/vegastack/vegastack-labs/internal/api"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/inventory"
	"github.com/vegastack/vegastack-labs/internal/inventoryops"
	"github.com/vegastack/vegastack-labs/internal/localapi"
	"github.com/vegastack/vegastack-labs/internal/result"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/stateexport"
	"github.com/vegastack/vegastack-labs/internal/store"
)

const productionDatabasePath = "/var/lib/vsk-labs/control.db"

type Operations struct {
	build        result.BuildInfo
	requestIDs   result.RequestIDSource
	openStore    func(context.Context, store.Config) (*store.Store, error)
	databasePath string
}

func NewOperations(build result.BuildInfo, requestIDs result.RequestIDSource) *Operations {
	return &Operations{build: build, requestIDs: requestIDs, openStore: store.Open, databasePath: productionDatabasePath}
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
	authority, err := operations.openStore(ctx, store.Config{DatabasePath: operations.databasePath, Mode: store.OpenExisting, ExpectedUID: profile.SocketOwnerUID, ToolVersion: operations.build.ToolVersion, BuildVersion: operations.build.ReleaseBuildID})
	if err != nil {
		return err
	}
	authorizer := store.NewReadAuthorizer(authority)
	reads := store.NewReadRepository(authority)
	streamer, err := api.NewEventStreamer(api.NewStoreEventSource(reads, authority), authorizer, api.ProductionStreamLimits)
	if err != nil {
		_ = authority.Close()
		return err
	}
	application, err := api.NewApplication(api.Config{Authority: authority, Authorizer: authorizer, Reads: reads, Results: factory, Cursors: nil, Queries: nil, Streams: streamer})
	if err != nil {
		streamer.Close()
		_ = authority.Close()
		return err
	}
	decoders := inventoryops.NewDecoderRegistry()
	imports, err := inventory.NewService(store.NewInventoryDraftRepository(authority), nil, nil)
	if err != nil {
		_ = application.Shutdown(ctx)
		return err
	}
	diffs, err := inventoryops.NewDiffService(store.NewInventoryDraftRepository(authority), decoders)
	if err != nil {
		_ = application.Shutdown(ctx)
		return err
	}
	artifacts, err := store.NewInventoryExportArtifactStore(store.InventoryExportArtifactConfig{Root: profile.InventoryExportRoot, ExpectedUID: profile.SocketOwnerUID})
	if err != nil {
		_ = application.Shutdown(ctx)
		return err
	}
	exportRepository := store.NewInventoryExportRepository(authority)
	exports, err := stateexport.NewService(stateexport.Config{Source: exportRepository, Audit: exportRepository, Artifacts: artifacts, Build: operations.build})
	if err != nil {
		_ = application.Shutdown(ctx)
		return err
	}
	if err := api.RegisterInventoryOperations(application, api.InventoryOperationConfig{Authorizer: authorizer, Decoders: decoders, Imports: imports, Diffs: diffs, Exports: exports, Results: factory}); err != nil {
		_ = application.Shutdown(ctx)
		return err
	}
	service, err := New(Config{Profile: profile, Application: application, Results: factory, PlatformProbe: fixedPlatformProbe{platform: platform}})
	if err != nil {
		_ = application.Shutdown(ctx)
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
