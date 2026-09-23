package server

import (
	"context"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/vegastack/vegastack-labs/internal/acknowledgement"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/adapter/backuptrust"
	"github.com/vegastack/vegastack-labs/internal/adapter/localbackup"
	"github.com/vegastack/vegastack-labs/internal/api"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/backup"
	"github.com/vegastack/vegastack-labs/internal/change"
	"github.com/vegastack/vegastack-labs/internal/clientprofile"
	"github.com/vegastack/vegastack-labs/internal/consoleassets"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/inventory"
	"github.com/vegastack/vegastack-labs/internal/inventoryops"
	"github.com/vegastack/vegastack-labs/internal/localapi"
	planengine "github.com/vegastack/vegastack-labs/internal/plan"
	"github.com/vegastack/vegastack-labs/internal/result"
	runengine "github.com/vegastack/vegastack-labs/internal/run"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/stateexport"
	"github.com/vegastack/vegastack-labs/internal/store"
)

// productionDatabasePath remains fixed in normal builds. The Phase 3 acceptance
// verifier replaces this string at link time in its isolated test executable so
// it can exercise the real command boundary without adding a runtime override.
var productionDatabasePath = "/var/lib/vsk-labs/control.db"

type Operations struct {
	build              result.BuildInfo
	requestIDs         result.RequestIDSource
	openStore          func(context.Context, store.Config) (*store.Store, error)
	databasePath       string
	platformProbe      PlatformProbe
	identityHTTPClient *http.Client
}

func NewOperations(build result.BuildInfo, requestIDs result.RequestIDSource) *Operations {
	return &Operations{
		build: build, requestIDs: requestIDs, openStore: store.Open,
		databasePath: productionDatabasePath, platformProbe: NewRuntimePlatformProbe(),
		identityHTTPClient: &http.Client{Timeout: 10 * time.Second},
	}
}

func (operations *Operations) Run(ctx context.Context, configPath string) error {
	platform, err := operations.platformProbe.Current(ctx)
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
	declarationRepository := store.NewDeclarationRepository(authority)
	declarations, err := change.NewService(declarationRepository, time.Now)
	if err != nil {
		_ = application.Shutdown(ctx)
		return err
	}
	planRepository := store.NewPlanRepository(authority)
	if err := api.RegisterAuditOperations(application, api.AuditOperations{Audit: authority, Revisions: planRepository, Declarations: declarations, Results: factory}); err != nil {
		_ = application.Shutdown(ctx)
		return err
	}
	effectiveAuthorization := store.NewEffectiveAuthorizationRepository(authority)
	observations, err := planengine.NewStateObservationReader(planRepository)
	if err != nil {
		_ = application.Shutdown(ctx)
		return err
	}
	plans, err := planengine.NewService(planengine.Config{Repository: planRepository, Observations: observations, Clock: time.Now, PolicyVersion: "1.0.0", ToolVersion: operations.build.ToolVersion, ContractVersion: "1.0.0", Risk: "destructive", AuthorizationBranch: "human", ExecutorMode: "central", OperationExecutorID: "executor-central"})
	if err != nil {
		_ = application.Shutdown(ctx)
		return err
	}
	effectiveConfig := api.EffectiveAuthorizationConfig{Authorizer: authorization.NewEvaluator(effectiveAuthorization), Recorder: effectiveAuthorization, Clock: time.Now}
	if err := api.RegisterDeclarationPlanOperations(application, api.DeclarationPlanConfig{
		Declarations:  declarations,
		Plans:         plans,
		Results:       factory,
		Authorization: effectiveConfig,
	}); err != nil {
		_ = application.Shutdown(ctx)
		return err
	}
	acknowledgements, err := acknowledgement.NewService(acknowledgement.Config{
		Repository: store.NewAcknowledgementRepository(authority),
		Plans:      acknowledgementPlanReader{plans: plans},
		Authorizer: authorization.NewEvaluator(effectiveAuthorization),
		Clock:      time.Now,
	})
	if err != nil {
		_ = application.Shutdown(ctx)
		return err
	}
	var acknowledgementScopes api.AcknowledgementScopeResolver = unavailableAcknowledgementScope{}
	var acknowledgementPublisher api.AcknowledgementPublisher = unavailableAcknowledgementPublisher{}
	var acknowledgementBackground BackgroundService
	if profile.AcknowledgementAdapterConfigPath != "" {
		runtime, runtimeErr := composeSlackAcknowledgement(ctx, profile.AcknowledgementAdapterConfigPath, profile.SocketOwnerUID, acknowledgements)
		if runtimeErr == nil {
			acknowledgementScopes = runtime.scopes
			acknowledgementPublisher = runtime.publisher
			acknowledgementBackground = runtime.background
		}
	}
	if err := api.RegisterAcknowledgementOperations(application, api.AcknowledgementOperationConfig{
		Plans: plans, Acknowledgements: acknowledgements, Scopes: acknowledgementScopes,
		Publisher: acknowledgementPublisher, Results: factory,
	}); err != nil {
		_ = application.Shutdown(ctx)
		return err
	}
	runRepository := store.NewRunRepository(authority)
	leaseRepository := store.NewExecutorLeaseRepository(authority)
	admission := runengine.NewAdmissionGate(acknowledgements, time.Now)
	adapters := productionAdapterRegistry()
	backupRepository := store.NewBackupRepository(authority)
	// The protected local backup adapter is registered only when the complete
	// standard/critical/restic profile triplet is present. It fails closed
	// off-Linux and its effect always runs through the exact bound credential
	// path; a partial or absent profile leaves it unregistered.
	if profile.LocalBackup != nil {
		snapshots, snapshotErr := store.NewOnlineSnapshotSource(authority)
		if snapshotErr != nil {
			_ = application.Shutdown(ctx)
			return snapshotErr
		}
		inspector, inspectErr := store.NewRestoredSQLiteInspector(authority)
		if inspectErr != nil {
			_ = application.Shutdown(ctx)
			return inspectErr
		}
		localTrust := localbackup.NewProtectedLocalDependencyTrust()
		localAdapter, adapterErr := localbackup.New(localbackup.Config{
			LocalBackup: profile.LocalBackup,
			ExpectedUID: profile.SocketOwnerUID,
			Backups:     backupRepository,
			Snapshots:   snapshots,
			Inspector:   inspector,
			Trust:       backuptrust.NewVerifier(backupRepository, backuptrust.UnavailableArtifactReader{}, localTrust),
			LiveProof:   true,
			Plans:       plans,
			Hooks:       backup.DefaultHookRegistry(),
			Runner:      backup.NewResticRunner(),
			Clock:       time.Now,
		})
		if adapterErr == nil {
			if registerErr := adapters.Register(localbackup.AdapterID, localAdapter); registerErr != nil {
				_ = application.Shutdown(ctx)
				return registerErr
			}
		}
	}
	gateRepository := store.NewGateRepository(authority)
	if err := api.RegisterGateOperations(application, api.GateOperations{Gates: gateRepository, Revisions: planRepository, Declarations: declarations, Results: factory, Build: operations.build, Clock: time.Now}); err != nil {
		_ = application.Shutdown(ctx)
		return err
	}
	coreGate, err := runengine.NewCoreGateEffect(gateRepository, store.NewAcknowledgementRepository(authority), operations.build.ReleaseBuildID, operations.build.ToolVersion, time.Now)
	if err != nil {
		_ = application.Shutdown(ctx)
		return err
	}
	credentialRepository := store.NewCredentialRepository(authority)
	credentialStep := &runengine.CredentialStep{Bindings: credentialRepository, Resolvers: adapters, Profiles: gateRepository, Plans: plans, Clock: time.Now}
	credentialCore, err := runengine.NewCoreCredentialEffect(credentialRepository, store.NewAcknowledgementRepository(authority), runengine.UnavailableGateVerifier{}, composeNativeCredentialLifecycleVerifier(ctx, operations.databasePath, profile.SocketOwnerUID), runengine.UnavailableCredentialRecoveryVerifier{}, time.Now)
	if err != nil {
		_ = application.Shutdown(ctx)
		return err
	}
	runs, err := runengine.NewEngine(runengine.Config{Repository: runRepository, Plans: plans, Admission: admission, Adapters: adapters, Core: coreGate, CredentialCore: credentialCore, SecretGate: runengine.UnavailableGateVerifier{}, CredentialStep: credentialStep, Clock: time.Now, ExecutionContext: ctx})
	if err != nil {
		_ = application.Shutdown(ctx)
		return err
	}
	if err := api.RegisterRunOperations(application, api.RunOperationConfig{Runs: runs, Plans: plans, Acknowledgements: acknowledgements, Results: factory, Authorization: effectiveConfig}); err != nil {
		_ = application.Shutdown(ctx)
		return err
	}
	executors, err := runengine.NewExternalExecutor(runengine.ExternalExecutorConfig{Runs: runRepository, Leases: leaseRepository, Plans: plans, Admission: admission, Adapters: adapters, Clock: time.Now})
	if err != nil {
		_ = application.Shutdown(ctx)
		return err
	}
	if err := api.RegisterExecutorOperations(application, api.ExecutorOperationConfig{Lifecycle: executors, Results: factory}); err != nil {
		_ = application.Shutdown(ctx)
		return err
	}
	credentialImports := newProductionCredentialImporter(credentialRepository, planRepository, operations.databasePath, profile.SocketOwnerUID)
	credentialLifecycle, err := api.NewCredentialLifecycleService(credentialRepository, planRepository, declarations, effectiveConfig.Authorizer)
	if err != nil {
		_ = application.Shutdown(ctx)
		return err
	}
	if err := api.RegisterCredentialLifecycleOperation(application, api.CredentialLifecycleOperations{Lifecycle: credentialLifecycle, Results: factory}); err != nil {
		_ = application.Shutdown(ctx)
		return err
	}
	if err := api.RegisterCredentialImportOperation(application, api.CredentialImportOperations{Imports: credentialImports, Results: factory}); err != nil {
		_ = application.Shutdown(ctx)
		return err
	}
	if err := api.RegisterBackupOperations(application, api.BackupOperations{Drafts: backupRepository, Status: backupRepository,
		Runs:    api.RunOperationConfig{Runs: runs, Plans: plans, Acknowledgements: acknowledgements, Results: factory, Authorization: effectiveConfig},
		Results: factory}); err != nil {
		_ = application.Shutdown(ctx)
		return err
	}
	if err := api.ValidateRegisteredRoutes(application); err != nil {
		_ = application.Shutdown(ctx)
		return err
	}
	background := backgroundServices{executors}
	if acknowledgementBackground != nil {
		background = append(background, acknowledgementBackground)
	}
	service, err := New(Config{Profile: profile, Application: application, Results: factory, PlatformProbe: fixedPlatformProbe{platform: platform}, Remote: remote, Background: background})
	if err != nil {
		_ = application.Shutdown(ctx)
		return err
	}
	return service.Run(ctx)
}

// productionAdapterRegistry is the single composition point for adapters that
// the shipped server may execute. Keeping the constructor explicit lets the
// acceptance suite prove that test-only adapters cannot enter the real runtime.
// It also starts with no credential resolver: the optional 1Password SDK seam
// requires an applied capability/profile and a native loaded service token,
// and #104 has no production live-proof verifier to admit secret steps.
func productionAdapterRegistry() *adapter.Registry {
	return adapter.NewRegistry()
}

// backgroundServices keeps optional capabilities inside the one vsk-labs
// process while allowing each capability to stop independently and fail closed.
type backgroundServices []BackgroundService

func (services backgroundServices) Run(ctx context.Context) error {
	var workers sync.WaitGroup
	for _, service := range services {
		if service == nil {
			continue
		}
		workers.Add(1)
		go func(background BackgroundService) {
			defer workers.Done()
			_ = background.Run(ctx)
		}(service)
	}
	<-ctx.Done()
	workers.Wait()
	return nil
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
	adapter, err := identity.NewCloudflareAccessAdapter(adapterConfig, operations.identityHTTPClient, time.Now)
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

func (operations *Operations) ImportCredential(ctx context.Context, configPath string, input generated.CredentialImportRequest, source io.Reader) (localapi.TypedResponse[generated.CredentialImportSubmission], error) {
	client, profile, err := operations.controlClient(ctx, configPath)
	if err != nil {
		return localapi.TypedResponse[generated.CredentialImportSubmission]{}, err
	}
	return client.ImportCredential(ctx, profile, input, source)
}

func (operations *Operations) CreateCredentialLifecycleDraft(ctx context.Context, configPath string, input generated.CredentialLifecycleRequest) (localapi.TypedResponse[generated.CredentialLifecycleSubmission], error) {
	client, profile, err := operations.controlClient(ctx, configPath)
	if err != nil {
		return localapi.TypedResponse[generated.CredentialLifecycleSubmission]{}, err
	}
	return client.CreateCredentialLifecycleDraft(ctx, profile, input)
}

func (operations *Operations) AuditCheckpoints(ctx context.Context, configPath string) (localapi.TypedResponse[generated.AuditCheckpointListData], error) {
	client, profile, err := operations.controlClient(ctx, configPath)
	if err != nil {
		return localapi.TypedResponse[generated.AuditCheckpointListData]{}, err
	}
	return client.AuditCheckpoints(ctx, profile)
}

func (operations *Operations) VerifyAudit(ctx context.Context, configPath string) (localapi.TypedResponse[generated.AuditVerificationData], error) {
	client, profile, err := operations.controlClient(ctx, configPath)
	if err != nil {
		return localapi.TypedResponse[generated.AuditVerificationData]{}, err
	}
	return client.VerifyAudit(ctx, profile)
}

func (operations *Operations) Gates(ctx context.Context, configPath string) (localapi.TypedResponse[generated.GateListData], error) {
	client, profile, err := operations.controlClient(ctx, configPath)
	if err != nil {
		return localapi.TypedResponse[generated.GateListData]{}, err
	}
	return client.Gates(ctx, profile)
}

func (operations *Operations) GetGate(ctx context.Context, configPath, gateID string) (localapi.TypedResponse[generated.GateView], error) {
	client, profile, err := operations.controlClient(ctx, configPath)
	if err != nil {
		return localapi.TypedResponse[generated.GateView]{}, err
	}
	return client.GetGate(ctx, profile, gateID)
}

func (operations *Operations) CheckGate(ctx context.Context, configPath, gateID, subjectID string) (localapi.TypedResponse[generated.GateEvaluation], error) {
	client, profile, err := operations.controlClient(ctx, configPath)
	if err != nil {
		return localapi.TypedResponse[generated.GateEvaluation]{}, err
	}
	return client.CheckGate(ctx, profile, gateID, subjectID)
}

func (operations *Operations) SubmitGateEvidence(ctx context.Context, configPath string, input generated.GateEvidenceRequest) (localapi.TypedResponse[generated.GateEvidenceSubmission], error) {
	client, profile, err := operations.controlClient(ctx, configPath)
	if err != nil {
		return localapi.TypedResponse[generated.GateEvidenceSubmission]{}, err
	}
	return client.SubmitGateEvidence(ctx, profile, input)
}

func (operations *Operations) SubmitProfileDraft(ctx context.Context, configPath string, input generated.GateProfileDraftRequest) (localapi.TypedResponse[generated.GateProfileDraftSubmission], error) {
	client, profile, err := operations.controlClient(ctx, configPath)
	if err != nil {
		return localapi.TypedResponse[generated.GateProfileDraftSubmission]{}, err
	}
	return client.SubmitProfileDraft(ctx, profile, input)
}

func (operations *Operations) SubmitBackupPolicyDraft(ctx context.Context, configPath string, input generated.BackupPolicyDraftRequest) (localapi.TypedResponse[generated.BackupPolicyDraftSubmission], error) {
	client, profile, err := operations.controlClient(ctx, configPath)
	if err != nil {
		return localapi.TypedResponse[generated.BackupPolicyDraftSubmission]{}, err
	}
	return client.SubmitBackupPolicyDraft(ctx, profile, input)
}

func (operations *Operations) BackupStatus(ctx context.Context, configPath string) (localapi.TypedResponse[generated.BackupStatusData], error) {
	client, profile, err := operations.controlClient(ctx, configPath)
	if err != nil {
		return localapi.TypedResponse[generated.BackupStatusData]{}, err
	}
	return client.BackupStatus(ctx, profile)
}

func (operations *Operations) RunBackup(ctx context.Context, configPath string, input generated.BackupRunRequest) (localapi.TypedResponse[generated.BackupJob], error) {
	client, profile, err := operations.controlClient(ctx, configPath)
	if err != nil {
		return localapi.TypedResponse[generated.BackupJob]{}, err
	}
	return client.RunBackup(ctx, profile, input)
}

func (operations *Operations) VerifyBackup(ctx context.Context, configPath string, input generated.BackupVerifyRequest) (localapi.TypedResponse[generated.BackupJob], error) {
	client, profile, err := operations.controlClient(ctx, configPath)
	if err != nil {
		return localapi.TypedResponse[generated.BackupJob]{}, err
	}
	return client.VerifyBackup(ctx, profile, input)
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

func (operations *Operations) Plan(ctx context.Context, configPath, declarationID string, revision int64) (localapi.TypedResponse[generated.Plan], error) {
	client, profile, err := operations.controlClient(ctx, configPath)
	if err != nil {
		return localapi.TypedResponse[generated.Plan]{}, err
	}
	return client.Plan(ctx, profile, declarationID, revision)
}

func (operations *Operations) Apply(ctx context.Context, configPath, planID string) (localapi.TypedResponse[generated.RunPresentation], error) {
	client, profile, err := operations.controlClient(ctx, configPath)
	if err != nil {
		return localapi.TypedResponse[generated.RunPresentation]{}, err
	}
	return client.Apply(ctx, profile, planID)
}

func (operations *Operations) InspectRun(ctx context.Context, configPath, runID string) (localapi.TypedResponse[generated.RunPresentation], error) {
	client, profile, err := operations.controlClient(ctx, configPath)
	if err != nil {
		return localapi.TypedResponse[generated.RunPresentation]{}, err
	}
	return client.InspectRun(ctx, profile, runID)
}

func (operations *Operations) CancelRun(ctx context.Context, configPath, runID string) (localapi.TypedResponse[generated.RunPresentation], error) {
	client, profile, err := operations.controlClient(ctx, configPath)
	if err != nil {
		return localapi.TypedResponse[generated.RunPresentation]{}, err
	}
	return client.CancelRun(ctx, profile, runID)
}

func (operations *Operations) ResumeRun(ctx context.Context, configPath, runID string) (localapi.TypedResponse[generated.RunPresentation], error) {
	client, profile, err := operations.controlClient(ctx, configPath)
	if err != nil {
		return localapi.TypedResponse[generated.RunPresentation]{}, err
	}
	return client.ResumeRun(ctx, profile, runID)
}

func (operations *Operations) controlClient(ctx context.Context, configPath string) (localapi.Client, serverconfig.Profile, error) {
	if profile, matched, err := clientprofile.Load(ctx, configPath); matched {
		if err != nil {
			return nil, serverconfig.Profile{}, err
		}
		return localapi.NewClient(result.NewFactory(operations.build, operations.requestIDs)), profile, nil
	}
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

type acknowledgementPlanReader struct{ plans *planengine.Service }

func (reader acknowledgementPlanReader) Get(ctx context.Context, planID string) (generated.Plan, error) {
	result, err := reader.plans.Get(ctx, planID)
	return result.Plan, err
}

func (reader acknowledgementPlanReader) ValidateCurrent(ctx context.Context, plan generated.Plan) error {
	return reader.plans.ValidateCurrent(ctx, plan)
}

// The Slack deployment profile and credential material are intentionally a
// later operator-controlled setup concern. Until supplied, the available local
// endpoint fails closed instead of adding a weaker approval path.
type unavailableAcknowledgementScope struct{}

func (unavailableAcknowledgementScope) Resolve(context.Context, generated.AcknowledgementRequest) (acknowledgement.Scope, error) {
	return acknowledgement.Scope{}, failure.New(generated.ErrorCodePrerequisiteBlocked, "slack-acknowledgement", false)
}

func (unavailableAcknowledgementScope) ResolvePlan(context.Context, generated.Plan) (acknowledgement.Scope, error) {
	return acknowledgement.Scope{}, failure.New(generated.ErrorCodePrerequisiteBlocked, "slack-acknowledgement", false)
}

type unavailableAcknowledgementPublisher struct{}

func (unavailableAcknowledgementPublisher) Publish(context.Context, acknowledgement.RequestCard) error {
	return failure.New(generated.ErrorCodeDependencyUnavailable, "slack-acknowledgement", true)
}
