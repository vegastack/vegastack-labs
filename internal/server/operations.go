package server

import (
	"context"
	"net/http"
	"time"

	"github.com/vegastack/vegastack-labs/internal/api"
	"github.com/vegastack/vegastack-labs/internal/consoleassets"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
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
	authorizer := newAuditingReadAuthorizer(store.NewReadAuthorizer(authority), authority)
	reads := store.NewReadRepository(authority)
	remote, sessions := operations.remoteRead(ctx, profile, authority, factory)
	streamer, err := api.NewEventStreamer(api.NewStoreEventSource(reads, authority), authorizer, api.ProductionStreamLimits)
	if err != nil {
		_ = authority.Close()
		return err
	}
	application, err := api.NewApplication(api.Config{Authority: authority, Authorizer: authorizer, Reads: reads, Results: factory, Cursors: nil, Queries: nil, Streams: streamer, Sessions: sessions})
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
	if err := api.RegisterInventoryOperations(application, api.InventoryOperationConfig{Decoders: decoders, Imports: imports, Diffs: diffs, Exports: exports, Results: factory}); err != nil {
		_ = application.Shutdown(ctx)
		return err
	}
	service, err := New(Config{Profile: profile, Application: application, Results: factory, PlatformProbe: fixedPlatformProbe{platform: platform}, Remote: remote})
	if err != nil {
		_ = application.Shutdown(ctx)
		return err
	}
	return service.Run(ctx)
}

func (operations *Operations) remoteRead(ctx context.Context, profile serverconfig.Profile, authority *store.Store, factory *result.Factory) (*RemoteConfig, api.BrowserSessionService) {
	if !profile.RemoteRead.Enabled {
		return nil, nil
	}
	unavailable := func(reason RemoteReadReason) (*RemoteConfig, api.BrowserSessionService) {
		return &RemoteConfig{PreflightFailure: reason}, nil
	}
	if !profile.RemoteRead.ConfigurationValid {
		return unavailable(RemoteReadReasonPreflightUnavailable)
	}
	adapterConfig, err := identity.LoadCloudflareAccessProfile(ctx, profile.RemoteRead.IdentityConfigPath)
	if err != nil {
		return unavailable(RemoteReadReasonAuthenticationFailed)
	}
	adapter, err := identity.NewCloudflareAccessAdapter(adapterConfig, &http.Client{Timeout: 10 * time.Second}, time.Now)
	if err != nil {
		return unavailable(RemoteReadReasonAuthenticationFailed)
	}
	files, manifest, err := consoleassets.Open()
	if err != nil {
		return unavailable(RemoteReadReasonPreflightUnavailable)
	}
	console, err := NewConsoleHandler(files, manifest)
	if err != nil {
		return unavailable(RemoteReadReasonPreflightUnavailable)
	}
	authenticator, err := NewBrowserAuthenticator(BrowserAuthConfig{
		ExactOrigin: profile.RemoteRead.PublicOrigin,
		ExactHost:   profile.RemoteRead.ExactHost,
		Identities:  adapter,
		Sessions:    authority,
		Results:     factory,
	})
	if err != nil {
		return unavailable(RemoteReadReasonAuthenticationFailed)
	}
	return &RemoteConfig{
		Authenticator: authenticator,
		Console:       console,
		ListenConfig: RemoteListenConfig{
			Address:         profile.RemoteRead.BindAddress,
			CertificatePath: profile.RemoteRead.TLSCertificatePath,
			PrivateKeyPath:  profile.RemoteRead.TLSPrivateKeyPath,
		},
	}, authenticator.SessionService()
}

func (operations *Operations) Status(ctx context.Context, configPath string) (localapi.Response, error) {
	client, profile, err := operations.controlClient(ctx, configPath)
	if err != nil {
		return localapi.Response{}, err
	}
	return client.Status(ctx, profile)
}

func (operations *Operations) Summary(ctx context.Context, configPath string) (localapi.TypedResponse[generated.ApiSummaryData], error) {
	client, profile, err := operations.controlClient(ctx, configPath)
	if err != nil {
		return localapi.TypedResponse[generated.ApiSummaryData]{}, err
	}
	return client.Summary(ctx, profile)
}

func (operations *Operations) DatabaseStatus(ctx context.Context, configPath string) (localapi.TypedResponse[generated.DatabaseStatusData], error) {
	client, profile, err := operations.controlClient(ctx, configPath)
	if err != nil {
		return localapi.TypedResponse[generated.DatabaseStatusData]{}, err
	}
	return client.DatabaseStatus(ctx, profile)
}

func (operations *Operations) ImportInventory(ctx context.Context, configPath string, request generated.InventoryImportRequest) (localapi.TypedResponse[generated.InventoryImportData], error) {
	client, profile, err := operations.controlClient(ctx, configPath)
	if err != nil {
		return localapi.TypedResponse[generated.InventoryImportData]{}, err
	}
	return client.ImportInventory(ctx, profile, request)
}

func (operations *Operations) DiffInventory(ctx context.Context, configPath string, request generated.InventoryDiffRequest) (localapi.TypedResponse[generated.InventoryDiffData], error) {
	client, profile, err := operations.controlClient(ctx, configPath)
	if err != nil {
		return localapi.TypedResponse[generated.InventoryDiffData]{}, err
	}
	return client.DiffInventory(ctx, profile, request)
}

func (operations *Operations) ExportInventory(ctx context.Context, configPath string, request generated.InventoryExportRequest) (localapi.TypedResponse[generated.InventoryExportData], error) {
	client, profile, err := operations.controlClient(ctx, configPath)
	if err != nil {
		return localapi.TypedResponse[generated.InventoryExportData]{}, err
	}
	return client.ExportInventory(ctx, profile, request)
}

func (operations *Operations) controlClient(ctx context.Context, configPath string) (localapi.Client, serverconfig.Profile, error) {
	ownerUID, err := currentServiceOwnerUID()
	if err != nil {
		return nil, serverconfig.Profile{}, failure.New(generated.ErrorCodeUnsupportedPlatform, "server-platform", false)
	}
	profile, err := serverconfig.NewLoader(ownerUID).Load(ctx, configPath)
	if err != nil {
		return nil, serverconfig.Profile{}, err
	}
	return localapi.NewClient(result.NewFactory(operations.build, operations.requestIDs)), profile, nil
}

type fixedPlatformProbe struct{ platform Platform }

func (probe fixedPlatformProbe) Current(context.Context) (Platform, error) {
	return probe.platform, nil
}
