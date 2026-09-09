//go:build linux

package store

import (
	"context"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/audit"
)

func TestOperationalAuditAdvancesSequenceButNotStateRevision(t *testing.T) {
	store := openAuditTestStore(t)
	before := readRevisionAndSequence(t, store)
	request := operationalAuditRequest("b", []audit.OutboxRequirement{{Destination: "audit-primary", Enabled: true}})
	result, err := store.AppendOperationalAudit(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	after := readRevisionAndSequence(t, store)
	if result.StateRevision != 0 || after.StateRevision != before.StateRevision || after.AuditSequence != before.AuditSequence+1 {
		t.Fatalf("before/result/after = %#v / %#v / %#v", before, result, after)
	}
	replay, err := store.AppendOperationalAudit(context.Background(), request)
	if err != nil || replay.Created || readRevisionAndSequence(t, store) != after {
		t.Fatalf("replay = %#v, %v", replay, err)
	}
	assertAuditCounts(t, store, map[string]int{"audit_business": 0, "audit_events": 1, "intent_keys": 1, "outbox": 1})
}

func TestOperationalAuditRequiresExactRevisionAndCannotMutateBusiness(t *testing.T) {
	store := openAuditTestStore(t)
	request := operationalAuditRequest("c", nil)
	request.Expected.StateRevision = 1
	if _, err := store.AppendOperationalAudit(context.Background(), request); Code(err) != "STATE_CONFLICT" {
		t.Fatalf("stale code = %q", Code(err))
	}
	assertAuditCounts(t, store, map[string]int{"audit_business": 0, "audit_events": 0})
}

func operationalAuditRequest(fill string, destinations []audit.OutboxRequirement) OperationalAuditRequest {
	return OperationalAuditRequest{
		Expected:    RevisionToken{},
		Idempotency: audit.IntentKey{Scope: "operational-audit", KeyDigest: audit.Fingerprint("sha256:" + strings.Repeat(fill, 64)), RequestDigest: audit.Fingerprint("sha256:" + strings.Repeat(fill, 64))},
		Event: audit.EventDraft{
			Type: "inventory.export.requested", CorrelationID: "request-operational-" + fill,
			Attribution: audit.Attribution{AuthenticatedPrincipalID: "principal-test-1", AuthenticatedPrincipalMethod: "local-os-peer"},
			Target:      audit.Target{Kind: "inventory-draft", ID: "draft-operational-" + fill},
		},
		Destinations: destinations,
	}
}
