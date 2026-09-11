package readmodel

import (
	"errors"
	"time"
)

type SourceID string

const (
	SourceDatabase  SourceID = "database"
	SourceNodes     SourceID = "nodes"
	SourceGates     SourceID = "gates"
	SourcePeople    SourceID = "people"
	SourceServices  SourceID = "services"
	SourceBackups   SourceID = "backups"
	SourceProviders SourceID = "providers"
)

var sourceIDs = [...]SourceID{
	SourceDatabase,
	SourceNodes,
	SourceGates,
	SourcePeople,
	SourceServices,
	SourceBackups,
	SourceProviders,
}

func SourceIDValues() []SourceID {
	return append([]SourceID(nil), sourceIDs[:]...)
}

type SourceState string

const (
	SourceHealthy     SourceState = "healthy"
	SourceStale       SourceState = "stale"
	SourceUnknown     SourceState = "unknown"
	SourceUnavailable SourceState = "unavailable"
	SourceFailed      SourceState = "failed"
)

const (
	SourceReasonHealthy     = "source observation is current"
	SourceReasonStale       = "source observation is stale"
	SourceReasonUnknown     = "source has no observation timestamp"
	SourceReasonUnavailable = "source capability is unavailable"
	SourceReasonFailed      = "source reported a collection failure"
)

var ErrInvalidSource = errors.New("invalid source observation")

type SourceObservation struct {
	ID            SourceID
	Capability    string
	Available     bool
	CollectedAt   *time.Time
	LastSuccessAt *time.Time
	LastErrorAt   *time.Time
	FailureCode   string
}

type SourcePolicy struct {
	StaleAfter time.Duration
}

type SourceStatus struct {
	ID            SourceID
	Capability    string
	State         SourceState
	CollectedAt   *time.Time
	LastSuccessAt *time.Time
	LastErrorAt   *time.Time
	Reason        string
}

type SourceCounts struct {
	Total       int64
	Healthy     int64
	Stale       int64
	Unknown     int64
	Unavailable int64
	Failed      int64
}

type SourceListQuery struct {
	Limit        int
	Sort         string
	Source       SourceID
	State        SourceState
	AfterID      SourceID
	EvaluationAt time.Time
}

type SourcePage struct {
	Items        []SourceStatus
	HasMore      bool
	Last         SourceID
	Snapshot     RevisionToken
	EvaluationAt time.Time
}

func EvaluateSource(observation SourceObservation, policy SourcePolicy, now time.Time) (SourceStatus, error) {
	if !validSourceID(observation.ID) || observation.Capability == "" || policy.StaleAfter <= 0 || now.IsZero() {
		return SourceStatus{}, ErrInvalidSource
	}
	status := SourceStatus{
		ID:            observation.ID,
		Capability:    observation.Capability,
		CollectedAt:   copyTime(observation.CollectedAt),
		LastSuccessAt: copyTime(observation.LastSuccessAt),
		LastErrorAt:   copyTime(observation.LastErrorAt),
	}
	switch {
	case !observation.Available:
		status.State, status.Reason = SourceUnavailable, SourceReasonUnavailable
	case observation.FailureCode != "":
		status.State, status.Reason = SourceFailed, SourceReasonFailed
	case observation.CollectedAt == nil:
		status.State, status.Reason = SourceUnknown, SourceReasonUnknown
	case observation.CollectedAt.After(now):
		status.State, status.Reason = SourceFailed, SourceReasonFailed
	case now.Sub(*observation.CollectedAt) > policy.StaleAfter:
		status.State, status.Reason = SourceStale, SourceReasonStale
	default:
		status.State, status.Reason = SourceHealthy, SourceReasonHealthy
	}
	return status, nil
}

func SummarizeSources(statuses []SourceStatus) (SourceCounts, SourceState) {
	counts := SourceCounts{Total: int64(len(statuses))}
	worst := SourceHealthy
	worstRank := 0
	for _, status := range statuses {
		var rank int
		switch status.State {
		case SourceHealthy:
			counts.Healthy++
			rank = 0
		case SourceUnavailable:
			counts.Unavailable++
			rank = 1
		case SourceUnknown:
			counts.Unknown++
			rank = 2
		case SourceStale:
			counts.Stale++
			rank = 3
		case SourceFailed:
			counts.Failed++
			rank = 4
		}
		if rank > worstRank {
			worst, worstRank = status.State, rank
		}
	}
	return counts, worst
}

func validSourceID(id SourceID) bool {
	for _, candidate := range sourceIDs {
		if candidate == id {
			return true
		}
	}
	return false
}

func ValidSourceID(id SourceID) bool { return validSourceID(id) }

func ValidSourceState(state SourceState) bool {
	switch state {
	case SourceHealthy, SourceStale, SourceUnknown, SourceUnavailable, SourceFailed:
		return true
	default:
		return false
	}
}

func SourceCapability(id SourceID) string {
	switch id {
	case SourceDatabase:
		return "database.status.read"
	case SourceNodes:
		return "inventory.node.read"
	case SourceGates:
		return "gate.read"
	case SourcePeople:
		return "identity.person.read"
	case SourceServices:
		return "service.read"
	case SourceBackups:
		return "backup.status.read"
	case SourceProviders:
		return "adapter.status.read"
	default:
		return ""
	}
}

func SourceReason(state SourceState) string {
	switch state {
	case SourceHealthy:
		return SourceReasonHealthy
	case SourceStale:
		return SourceReasonStale
	case SourceUnknown:
		return SourceReasonUnknown
	case SourceUnavailable:
		return SourceReasonUnavailable
	case SourceFailed:
		return SourceReasonFailed
	default:
		return ""
	}
}

func copyTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copyValue := value.UTC()
	return &copyValue
}
