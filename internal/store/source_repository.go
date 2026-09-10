package store

import (
	"context"
	"database/sql"
	"sort"
	"time"

	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/readmodel"
)

const (
	localSourceStaleAfter    = 24 * time.Hour
	optionalSourceStaleAfter = time.Hour
)

type SourceObserver interface {
	Observe(context.Context, readmodel.SourceID) (readmodel.SourceObservation, error)
}

type SourceRepository struct {
	store    *Store
	observer SourceObserver
}

func NewSourceRepository(store *Store, observer SourceObserver) *SourceRepository {
	return &SourceRepository{store: store, observer: observer}
}

func (repository *SourceRepository) ListSources(ctx context.Context, scope authorization.ReadScope, query readmodel.SourceListQuery, snapshot RevisionToken) (readmodel.SourcePage, error) {
	if query.Limit < 1 || query.Limit > 200 || (query.Sort != "id-asc" && query.Sort != "id-desc") || !sourceFilterValid(query.Source) || !stateFilterValid(query.State) {
		return readmodel.SourcePage{}, newStoreError(generated.ErrorCodeInputInvalid, "source-read", false, nil)
	}
	result := readmodel.SourcePage{Snapshot: readmodel.RevisionToken{StateRevision: snapshot.StateRevision, RecoveryEpoch: snapshot.RecoveryEpoch}}
	err := repository.store.Read(ctx, func(tx ReadTx) error {
		if err := verifySnapshot(ctx, tx, snapshot); err != nil {
			return err
		}
		if err := verifyReadScope(ctx, tx, scope, ""); err != nil {
			return err
		}
		allowed, all, err := allowedSources(ctx, tx, scope)
		if err != nil {
			return err
		}
		statuses, err := repository.evaluate(ctx, tx)
		if err != nil {
			return err
		}
		for _, status := range statuses {
			if !all && !allowed[status.ID] {
				continue
			}
			if query.Source != "" && query.Source != status.ID || query.State != "" && query.State != status.State {
				continue
			}
			result.Items = append(result.Items, status)
		}
		sort.Slice(result.Items, func(i, j int) bool {
			if query.Sort == "id-desc" {
				return result.Items[i].ID > result.Items[j].ID
			}
			return result.Items[i].ID < result.Items[j].ID
		})
		if query.AfterID != "" {
			items := result.Items[:0]
			for _, item := range result.Items {
				if query.Sort == "id-desc" && item.ID < query.AfterID || query.Sort == "id-asc" && item.ID > query.AfterID {
					items = append(items, item)
				}
			}
			result.Items = items
		}
		if len(result.Items) > query.Limit {
			result.Items = result.Items[:query.Limit]
			result.HasMore = true
			result.Last = result.Items[len(result.Items)-1].ID
		}
		return nil
	})
	return result, err
}

func (repository *SourceRepository) evaluate(ctx context.Context, tx ReadTx) ([]readmodel.SourceStatus, error) {
	observations, err := repository.observations(ctx, tx)
	if err != nil {
		return nil, err
	}
	now := repository.store.config.Clock().UTC()
	statuses := make([]readmodel.SourceStatus, 0, len(observations))
	for _, observation := range observations {
		policy := readmodel.SourcePolicy{StaleAfter: optionalSourceStaleAfter}
		if observation.ID == readmodel.SourceDatabase || observation.ID == readmodel.SourceNodes {
			policy.StaleAfter = localSourceStaleAfter
		}
		status, evaluateErr := readmodel.EvaluateSource(observation, policy, now)
		if evaluateErr != nil {
			return nil, newStoreError(generated.ErrorCodeIntegrityFailure, "source-observation", false, evaluateErr)
		}
		statuses = append(statuses, status)
	}
	return statuses, nil
}

func (repository *SourceRepository) observations(ctx context.Context, tx ReadTx) ([]readmodel.SourceObservation, error) {
	health := repository.store.health
	database := readmodel.SourceObservation{
		ID:            readmodel.SourceDatabase,
		Capability:    readmodel.SourceCapability(readmodel.SourceDatabase),
		Available:     true,
		CollectedAt:   health.LastIntegrityCheckAt,
		LastSuccessAt: health.LastIntegrityCheckAt,
	}
	if health.Mode == DatabaseSafeMode || health.IntegrityStatus == IntegrityFailed {
		database.FailureCode = "DATABASE_UNHEALTHY"
	}

	var observed sql.NullString
	if err := tx.queryRow(ctx, `SELECT MAX(observed_at) FROM inventory_draft_observations`).Scan(&observed); err != nil {
		return nil, err
	}
	nodes := readmodel.SourceObservation{ID: readmodel.SourceNodes, Capability: readmodel.SourceCapability(readmodel.SourceNodes), Available: true}
	if observed.Valid {
		value, err := time.Parse(time.RFC3339Nano, observed.String)
		if err != nil {
			return nil, newStoreError(generated.ErrorCodeIntegrityFailure, "source-observation", false, err)
		}
		nodes.CollectedAt, nodes.LastSuccessAt = &value, &value
	}
	result := []readmodel.SourceObservation{database, nodes}
	for _, id := range []readmodel.SourceID{readmodel.SourceGates, readmodel.SourcePeople, readmodel.SourceServices, readmodel.SourceBackups, readmodel.SourceProviders} {
		observation := readmodel.SourceObservation{ID: id, Capability: readmodel.SourceCapability(id), Available: false}
		if repository.observer != nil {
			candidate, err := repository.observer.Observe(ctx, id)
			if err != nil {
				observation.Available = true
				observation.FailureCode = "SOURCE_FAILED"
				now := repository.store.config.Clock().UTC()
				observation.LastErrorAt = &now
			} else {
				observation.Available = candidate.Available
				observation.CollectedAt = candidate.CollectedAt
				observation.LastSuccessAt = candidate.LastSuccessAt
				observation.LastErrorAt = candidate.LastErrorAt
				observation.FailureCode = candidate.FailureCode
			}
		}
		result = append(result, observation)
	}
	return result, nil
}

func allowedSources(ctx context.Context, tx ReadTx, scope authorization.ReadScope) (map[readmodel.SourceID]bool, bool, error) {
	rows, err := tx.query(ctx, `SELECT resource_id FROM read_grants WHERE principal_id=? AND capability=? AND resource_kind=? AND status='active' AND grant_revision=? ORDER BY resource_id`, scope.PrincipalID, scope.Capability, scope.ResourceKind, scope.GrantRevision)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	allowed := make(map[readmodel.SourceID]bool)
	all := false
	for rows.Next() {
		var resource string
		if err := rows.Scan(&resource); err != nil {
			return nil, false, err
		}
		if resource == "" {
			all = true
			continue
		}
		id := readmodel.SourceID(resource)
		if sourceFilterValid(id) {
			allowed[id] = true
		}
	}
	return allowed, all, rows.Err()
}

func sourceFilterValid(value readmodel.SourceID) bool {
	if value == "" {
		return true
	}
	for _, id := range readmodel.SourceIDs {
		if value == id {
			return true
		}
	}
	return false
}

func stateFilterValid(value readmodel.SourceState) bool {
	switch value {
	case "", readmodel.SourceHealthy, readmodel.SourceStale, readmodel.SourceUnknown, readmodel.SourceUnavailable, readmodel.SourceFailed:
		return true
	default:
		return false
	}
}
