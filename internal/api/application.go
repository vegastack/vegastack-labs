package api

import (
	"context"
	"crypto/rand"
	"net/http"
	"sync"
	"time"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/inventory"
	"github.com/vegastack/vegastack-labs/internal/readmodel"
	"github.com/vegastack/vegastack-labs/internal/result"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type Authority interface {
	Health(context.Context) (store.Health, error)
	Close() error
}

type SourceRepository interface {
	ListSources(context.Context, authorization.ReadScope, readmodel.SourceListQuery, store.RevisionToken) (readmodel.SourcePage, error)
}

type ReadRepository interface {
	SourceRepository
	CurrentRevision(context.Context, authorization.ReadScope) (store.RevisionToken, error)
	DatabaseStatus(context.Context, authorization.ReadScope) (readmodel.DatabaseStatus, error)
	Summary(context.Context, authorization.ReadScope) (readmodel.Summary, error)
	ListDrafts(context.Context, authorization.ReadScope, inventory.DraftListQuery, store.RevisionToken) (readmodel.DraftPage, error)
	GetDraft(context.Context, authorization.ReadScope, inventory.DraftRef) (readmodel.Draft, error)
	ListRecords(context.Context, authorization.ReadScope, inventory.DraftRef, inventory.RecordListQuery, store.RevisionToken) (readmodel.RecordPage, error)
	GetRecord(context.Context, authorization.ReadScope, inventory.DraftRef, string, inventory.LocalID) (readmodel.Record, error)
	ReadEvents(context.Context, authorization.ReadScope, audit.EventID, int) (readmodel.EventBatch, error)
	EventHighWater(context.Context, authorization.ReadScope) (audit.EventID, error)
	EventExists(context.Context, authorization.ReadScope, audit.EventID) (bool, error)
}

type BrowserSessionResult struct {
	Data   generated.ApiBrowserSessionData
	Cookie *http.Cookie
}

type BrowserSessionService interface {
	Create(context.Context) (BrowserSessionResult, error)
	Renew(context.Context) (BrowserSessionResult, error)
	Logout(context.Context) (BrowserSessionResult, error)
}

type Config struct {
	Authority  Authority
	Authorizer authorization.ReadAuthorizer
	Reads      ReadRepository
	Results    *result.Factory
	Cursors    CursorCodec
	Queries    QueryDecoder
	Streams    *EventStreamer
	Sessions   BrowserSessionService
}

type Application struct {
	config         Config
	effective      EffectiveAuthorizationConfig
	runs           RunLifecycle
	executors      ExecutorLifecycle
	routes         []route
	runSubmitGuard sync.Mutex
	runSubmits     map[string]*runSubmitLock
	closeOnce      sync.Once
	closeErr       error
}

type runSubmitLock struct {
	mutex sync.Mutex
	users int
}

func (app *Application) lockRunSubmit(key string) func() {
	app.runSubmitGuard.Lock()
	if app.runSubmits == nil {
		app.runSubmits = map[string]*runSubmitLock{}
	}
	lock := app.runSubmits[key]
	if lock == nil {
		lock = &runSubmitLock{}
		app.runSubmits[key] = lock
	}
	lock.users++
	app.runSubmitGuard.Unlock()
	lock.mutex.Lock()
	return func() {
		lock.mutex.Unlock()
		app.runSubmitGuard.Lock()
		lock.users--
		if lock.users == 0 {
			delete(app.runSubmits, key)
		}
		app.runSubmitGuard.Unlock()
	}
}

func NewApplication(config Config) (*Application, error) {
	if config.Authority == nil || config.Authorizer == nil || config.Reads == nil || config.Results == nil {
		return nil, apiFailure("INPUT_INVALID", "api-config")
	}
	if config.Cursors == nil {
		codec, err := NewCursorCodec(rand.Reader, time.Now)
		if err != nil {
			return nil, err
		}
		config.Cursors = codec
	}
	if config.Queries == nil {
		config.Queries = NewQueryDecoder()
	}
	app := &Application{config: config}
	app.routes = finiteRoutes(app)
	if !routesAreGeneratedSubset(app.routes) {
		return nil, apiFailure("INTEGRITY_FAILURE", "endpoint-registry")
	}
	return app, nil
}

func (app *Application) Start(ctx context.Context) error {
	if _, err := app.config.Authority.Health(ctx); err != nil {
		return err
	}
	if app.runs != nil {
		return app.runs.Startup(ctx)
	}
	return nil
}

func (app *Application) Health(ctx context.Context) (readmodel.ApplicationHealth, error) {
	health, err := app.config.Authority.Health(ctx)
	if err != nil {
		return readmodel.ApplicationHealth{}, err
	}
	return readmodel.ApplicationHealth{SafeMode: health.Mode == store.DatabaseSafeMode, RecoveryEpoch: health.Revision.RecoveryEpoch, StateRevision: health.Revision.StateRevision}, nil
}

func (app *Application) AuthorizeHealth(ctx context.Context, principal identity.Principal) error {
	_, err := app.config.Authorizer.AuthorizeRead(ctx, principal, authorization.ReadTarget{Capability: "control.health.read", ResourceKind: "control"})
	return err
}

func (app *Application) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	app.serve(writer, request)
}

func (app *Application) Shutdown(context.Context) error {
	if app.config.Streams != nil {
		app.config.Streams.Close()
	}
	app.closeOnce.Do(func() { app.closeErr = app.config.Authority.Close() })
	return app.closeErr
}
