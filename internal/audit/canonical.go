package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"
)

func CanonicalEvent(event Event) ([]byte, Fingerprint, error) {
	if event.Schema != EventSchema || event.SchemaVersion != EventSchemaVersion || event.EventID <= 0 || event.RecoveryEpoch < 0 || event.StateRevision < 0 {
		return nil, "", errInvalid
	}
	when, err := time.Parse(time.RFC3339Nano, event.OccurredAt)
	if err != nil || when.Location() != time.UTC || when.Format(time.RFC3339Nano) != event.OccurredAt {
		return nil, "", errInvalid
	}
	draft := EventDraft{
		Type: event.Type, CorrelationID: event.CorrelationID, CausationID: event.CausationID, CorrectionOf: event.CorrectionOf,
		Attribution: Attribution{AuthenticatedPrincipalID: event.PrincipalID, AuthenticatedPrincipalMethod: event.PrincipalMethod, ResponsibleHumanPrincipalID: event.HumanID},
		Target:      event.Target, Before: event.Before, After: event.After,
	}
	if event.AgentSource == nil {
		if event.AgentName != nil || event.AgentSessionID != nil {
			return nil, "", errInvalid
		}
	} else {
		if *event.AgentSource != "self-reported" || event.AgentName == nil || event.AgentSessionID == nil {
			return nil, "", errInvalid
		}
		draft.Attribution.Agent = &AgentMetadata{Name: *event.AgentName, SessionID: *event.AgentSessionID}
	}
	if err := ValidateEventDraft(draft); err != nil {
		return nil, "", err
	}
	payload, err := json.Marshal(event)
	if err != nil {
		return nil, "", errInvalid
	}
	sum := sha256.Sum256(payload)
	return payload, Fingerprint("sha256:" + hex.EncodeToString(sum[:])), nil
}

func EventFromDraft(draft EventDraft, id EventID, occurredAt time.Time, recoveryEpoch, stateRevision int64) (Event, error) {
	if err := ValidateEventDraft(draft); err != nil || id <= 0 || recoveryEpoch < 0 || stateRevision < 0 || occurredAt.Location() != time.UTC {
		return Event{}, errInvalid
	}
	event := Event{
		Schema: EventSchema, SchemaVersion: EventSchemaVersion, EventID: id,
		OccurredAt: occurredAt.Format(time.RFC3339Nano), RecoveryEpoch: recoveryEpoch, StateRevision: stateRevision,
		Type: draft.Type, CorrelationID: draft.CorrelationID, CausationID: draft.CausationID, CorrectionOf: draft.CorrectionOf,
		PrincipalID: draft.Attribution.AuthenticatedPrincipalID, PrincipalMethod: draft.Attribution.AuthenticatedPrincipalMethod,
		HumanID: draft.Attribution.ResponsibleHumanPrincipalID, Target: draft.Target, Before: draft.Before, After: draft.After,
	}
	if draft.Attribution.Agent != nil {
		name, session, source := draft.Attribution.Agent.Name, draft.Attribution.Agent.SessionID, "self-reported"
		event.AgentName, event.AgentSessionID, event.AgentSource = &name, &session, &source
	}
	return event, nil
}
