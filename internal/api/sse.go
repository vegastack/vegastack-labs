package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/readmodel"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type EventSource interface {
	ReadEvents(context.Context, authorization.ReadScope, audit.EventID, int) (readmodel.EventBatch, error)
	EventHighWater(context.Context, authorization.ReadScope) (audit.EventID, error)
	EventExists(context.Context, authorization.ReadScope, audit.EventID) (bool, error)
	SubscribeEventCommits() store.EventSubscription
}

type storeEventSource struct {
	reads ReadRepository
	store *store.Store
}

func NewStoreEventSource(reads ReadRepository, authority *store.Store) EventSource {
	return &storeEventSource{reads: reads, store: authority}
}
func (source *storeEventSource) ReadEvents(ctx context.Context, scope authorization.ReadScope, after audit.EventID, limit int) (readmodel.EventBatch, error) {
	return source.reads.ReadEvents(ctx, scope, after, limit)
}
func (source *storeEventSource) EventHighWater(ctx context.Context, scope authorization.ReadScope) (audit.EventID, error) {
	return source.reads.EventHighWater(ctx, scope)
}
func (source *storeEventSource) EventExists(ctx context.Context, scope authorization.ReadScope, id audit.EventID) (bool, error) {
	return source.reads.EventExists(ctx, scope, id)
}
func (source *storeEventSource) SubscribeEventCommits() store.EventSubscription {
	return source.store.SubscribeEventCommits()
}

type StreamLimits struct {
	BatchSize, SignalQueue    int
	Heartbeat, WriteDeadline  time.Duration
	MaxTotal, MaxPerPrincipal int
}

var ProductionStreamLimits = StreamLimits{BatchSize: 200, SignalQueue: 64, Heartbeat: 15 * time.Second, WriteDeadline: 5 * time.Second, MaxTotal: 16, MaxPerPrincipal: 4}

type EventStreamer struct {
	source     EventSource
	authorizer authorization.ReadAuthorizer
	limits     StreamLimits
	mu         sync.Mutex
	total      int
	principals map[string]int
	ctx        context.Context
	cancel     context.CancelFunc
}

func NewEventStreamer(source EventSource, authorizer authorization.ReadAuthorizer, limits StreamLimits) (*EventStreamer, error) {
	if source == nil || authorizer == nil || limits != ProductionStreamLimits {
		return nil, apiFailure(generated.ErrorCodeInputInvalid, "stream-config")
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &EventStreamer{source: source, authorizer: authorizer, limits: limits, principals: map[string]int{}, ctx: ctx, cancel: cancel}, nil
}
func (streamer *EventStreamer) Close() {
	if streamer != nil {
		streamer.cancel()
	}
}
func (streamer *EventStreamer) acquire(principal string) bool {
	streamer.mu.Lock()
	defer streamer.mu.Unlock()
	if streamer.total >= streamer.limits.MaxTotal || streamer.principals[principal] >= streamer.limits.MaxPerPrincipal {
		return false
	}
	streamer.total++
	streamer.principals[principal]++
	return true
}
func (streamer *EventStreamer) release(principal string) {
	streamer.mu.Lock()
	defer streamer.mu.Unlock()
	streamer.total--
	streamer.principals[principal]--
	if streamer.principals[principal] == 0 {
		delete(streamer.principals, principal)
	}
}

func (app *Application) serveEvents(w http.ResponseWriter, r *http.Request) {
	const endpoint = "api.v1.events.stream"
	if r.Method != http.MethodGet {
		app.failure(w, endpoint, apiFailure(generated.ErrorCodeInputInvalid, "method"))
		return
	}
	principal, ok := identity.PrincipalFromContext(r.Context())
	if !ok {
		app.failure(w, endpoint, apiFailure(generated.ErrorCodeAuthenticationRequired, "principal"))
		return
	}
	scope, err := app.config.Authorizer.AuthorizeRead(r.Context(), principal, authorization.ReadTarget{Capability: "audit.event.read", ResourceKind: "audit-event"})
	if err != nil {
		app.failure(w, endpoint, err)
		return
	}
	app.config.Streams.ServeHTTP(w, r, principal, scope, func(err error) { app.failure(w, endpoint, err) })
}

func (streamer *EventStreamer) ServeHTTP(w http.ResponseWriter, r *http.Request, principal identity.Principal, scope authorization.ReadScope, preStreamFailure func(error)) {
	raw, present := r.Header["Last-Event-Id"]
	if len(raw) > 1 {
		preStreamFailure(apiFailure(generated.ErrorCodeInputInvalid, "last-event-id"))
		return
	}
	var after audit.EventID
	if present {
		if len(raw) != 1 || raw[0] == "" || strings.HasPrefix(raw[0], "0") || strings.ContainsAny(raw[0], "+- ") {
			preStreamFailure(apiFailure(generated.ErrorCodeInputInvalid, "last-event-id"))
			return
		}
		id, err := strconv.ParseInt(raw[0], 10, 64)
		if err != nil || id <= 0 {
			preStreamFailure(apiFailure(generated.ErrorCodeInputInvalid, "last-event-id"))
			return
		}
		after = audit.EventID(id)
		exists, err := streamer.source.EventExists(r.Context(), scope, after)
		if err != nil {
			preStreamFailure(err)
			return
		}
		if !exists {
			preStreamFailure(apiFailure(generated.ErrorCodeStateConflict, "last-event-id"))
			return
		}
	}
	if !streamer.acquire(principal.ID) {
		preStreamFailure(apiFailure(generated.ErrorCodeDependencyUnavailable, "stream-capacity"))
		return
	}
	defer streamer.release(principal.ID)
	subscription := streamer.source.SubscribeEventCommits()
	defer subscription.Close()
	if !present {
		high, err := streamer.source.EventHighWater(r.Context(), scope)
		if err != nil {
			preStreamFailure(err)
			return
		}
		after = high
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher, ok := w.(http.Flusher)
	if !ok {
		return
	}
	flusher.Flush()
	heartbeat := time.NewTicker(streamer.limits.Heartbeat)
	defer heartbeat.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-streamer.ctx.Done():
			return
		default:
		}
		fresh, err := streamer.authorizer.AuthorizeRead(r.Context(), principal, authorization.ReadTarget{Capability: "audit.event.read", ResourceKind: "audit-event"})
		if err != nil || fresh.ScopeDigest != scope.ScopeDigest || fresh.GrantRevision != scope.GrantRevision {
			return
		}
		batch, err := streamer.source.ReadEvents(r.Context(), fresh, after, streamer.limits.BatchSize)
		if err != nil {
			return
		}
		if len(batch.Items) > 0 {
			for _, event := range batch.Items {
				body, err := json.Marshal(projectEvent(event))
				if err != nil {
					return
				}
				controller := http.NewResponseController(w)
				if err := controller.SetWriteDeadline(time.Now().Add(streamer.limits.WriteDeadline)); err != nil && !errors.Is(err, http.ErrNotSupported) {
					return
				}
				if _, err = fmt.Fprintf(w, "id: %d\nevent: audit-event\ndata: %s\n\n", event.EventID, body); err != nil {
					return
				}
				flusher.Flush()
				after = event.EventID
			}
			continue
		}
		select {
		case <-r.Context().Done():
			return
		case <-streamer.ctx.Done():
			return
		case _, ok := <-subscription.C():
			if !ok {
				return
			}
		case <-heartbeat.C:
			controller := http.NewResponseController(w)
			if err := controller.SetWriteDeadline(time.Now().Add(streamer.limits.WriteDeadline)); err != nil && !errors.Is(err, http.ErrNotSupported) {
				return
			}
			if _, err := fmt.Fprint(w, ": heartbeat\n\n"); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func projectEvent(event audit.Event) generated.ApiAuditEventData {
	var causation, correction *int64
	if event.CausationID != nil {
		x := int64(*event.CausationID)
		causation = &x
	}
	if event.CorrectionOf != nil {
		x := int64(*event.CorrectionOf)
		correction = &x
	}
	var before, after *string
	if event.Before != nil {
		x := string(*event.Before)
		before = &x
	}
	if event.After != nil {
		x := string(*event.After)
		after = &x
	}
	return generated.ApiAuditEventData{Event: generated.AuditEvent{Schema: event.Schema, SchemaVersion: event.SchemaVersion, EventID: int64(event.EventID), OccurredAt: event.OccurredAt, RecoveryEpoch: event.RecoveryEpoch, StateRevision: event.StateRevision, Type: string(event.Type), CorrelationID: event.CorrelationID, CausationEventID: causation, CorrectionOfEventID: correction, PrincipalID: event.PrincipalID, PrincipalMethod: event.PrincipalMethod, ResponsibleHumanPrincipalID: event.HumanID, AgentName: event.AgentName, AgentSessionID: event.AgentSessionID, AgentSource: event.AgentSource, Target: generated.AuditTarget{Kind: string(event.Target.Kind), ID: event.Target.ID}, BeforeFingerprint: before, AfterFingerprint: after}}
}
