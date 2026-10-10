package store

import (
	"bytes"
	"context"
	"encoding/json"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/linuxrole"
)

// NativeControlSetupAuthority is read from the current server-owned authority.
// It binds the original initialization audit/intent, not a fictional setup run.
type NativeControlSetupAuthority struct {
	SetupID, RequestDigest, ReviewDigest, InstanceID, HumanID, AuthorityID, InitializedAt string
	RecoveryEpoch, InitialEventID                                                         int64
	InitialEventDigest, InitialChainDigest                                                string
	VerifiedRestoreBinding                                                                *generated.RestoreBinding
}

func (r *GateRepository) nativeControlSetupAuthority(ctx context.Context, q nativeQuery, e NativeProducerExecution) (*NativeControlSetupAuthority, error) {
	if e.Plan.HostAction == nil || e.Plan.HostRoleScope == nil || e.Plan.HostRoleScope.RoleID != "control" || e.Receipt.Status != "succeeded" {
		return nil, nativeError()
	}
	in, err := linuxrole.DecodeInput([]byte(e.Plan.HostAction.ActionInput))
	if err != nil || in.RoleID != "control" || in.HostID != e.Reference.HostID {
		return nil, nativeError()
	}
	return readNativeControlSetupAuthority(ctx, q, e.Plan.Binding.RecoveryEpoch)
}

func readNativeControlSetupAuthority(ctx context.Context, q nativeQuery, producerEpoch int64) (*NativeControlSetupAuthority, error) {
	var v NativeControlSetupAuthority
	var raw, contextRaw []byte
	var current, mode, payload, previous, contextDigest, linkDigest string
	var epoch, revision, sequence, chainEpoch int64
	var preAnchor bool
	if q.row(`SELECT instance_id,recovery_epoch,authority_mode FROM system_meta WHERE id=1`).Scan(&current, &epoch, &mode) != nil || mode != "ready" || epoch != producerEpoch {
		return nil, nativeError()
	}
	var count int
	if q.row(`SELECT COUNT(*) FROM intent_keys WHERE scope=?`, initialSetupScope).Scan(&count) != nil || count != 1 {
		return nil, nativeError()
	}
	err := q.row(`SELECT i.key_digest,i.request_digest,i.event_id,i.state_revision,i.recovery_epoch,a.canonical_payload,a.payload_sha256,l.instance_id,l.recovery_epoch,l.segment_sequence,l.previous_digest,l.context_bytes,l.context_digest,l.link_digest,l.pre_anchor FROM intent_keys i JOIN audit_events a ON a.event_id=i.event_id AND a.state_revision=i.state_revision AND a.recovery_epoch=i.recovery_epoch JOIN audit_chain_links l ON l.event_id=a.event_id AND l.payload_digest=a.payload_sha256 WHERE i.scope=?`, initialSetupScope).Scan(&v.ReviewDigest, &v.RequestDigest, &v.InitialEventID, &revision, &v.RecoveryEpoch, &raw, &payload, &v.InstanceID, &chainEpoch, &sequence, &previous, &contextRaw, &contextDigest, &linkDigest, &preAnchor)
	if err != nil || chainEpoch != v.RecoveryEpoch || v.RecoveryEpoch != 0 || !restoreDigest(v.ReviewDigest) || !restoreDigest(v.RequestDigest) {
		return nil, nativeError()
	}
	var event audit.Event
	if json.Unmarshal(raw, &event) != nil {
		return nil, nativeError()
	}
	canonical, digest, err := audit.CanonicalEvent(event)
	if err != nil || !bytes.Equal(raw, canonical) || string(digest) != payload || event.Type != "control.initialized" || int64(event.EventID) != v.InitialEventID || event.StateRevision != revision || event.RecoveryEpoch != v.RecoveryEpoch || event.After == nil || string(*event.After) != v.ReviewDigest || event.PrincipalMethod != "slack-socket-mode" || event.HumanID == nil || *event.HumanID != event.PrincipalID || event.Target.Kind != "acknowledgement-authority" {
		return nil, nativeError()
	}
	var ids struct {
		Domain           string `json:"domain"`
		RunID            string `json:"runId"`
		PlanID           string `json:"planId"`
		ProviderNativeID string `json:"providerNativeId"`
	}
	if json.Unmarshal(contextRaw, &ids) != nil {
		return nil, nativeError()
	}
	contextIDs := audit.ContextIDs{RunID: ids.RunID, PlanID: ids.PlanID, ProviderNativeID: ids.ProviderNativeID}
	canonicalContext, cd, err := audit.CanonicalContext(contextIDs)
	if err != nil || !bytes.Equal(canonicalContext, contextRaw) || string(cd) != contextDigest {
		return nil, nativeError()
	}
	link, err := audit.MakeChainLink(event, contextIDs, v.InstanceID, sequence, audit.Fingerprint(previous), preAnchor)
	if err != nil || string(link.LinkDigest) != linkDigest {
		return nil, nativeError()
	}
	if v.InstanceID != current || v.RecoveryEpoch != epoch {
		v.VerifiedRestoreBinding, err = nativeVerifiedRestoreBinding(ctx, q)
		b := v.VerifiedRestoreBinding
		if err != nil || b == nil || b.PriorInstanceID != v.InstanceID || b.PriorRecoveryEpoch != v.RecoveryEpoch || b.NewInstanceID != current || b.NextRecoveryEpoch != epoch {
			return nil, nativeError()
		}
	}
	v.SetupID = event.CorrelationID
	v.HumanID = event.PrincipalID
	v.AuthorityID = event.Target.ID
	v.InitializedAt = event.OccurredAt
	v.InitialEventDigest = hostaction.BytesDigest(raw)
	v.InitialChainDigest = linkDigest
	return &v, nil
}
