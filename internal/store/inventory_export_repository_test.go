//go:build linux

package store

import (
	"context"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/inventory"
	"github.com/vegastack/vegastack-labs/internal/stateexport"
)

func TestInventoryExportSnapshotPinsRevisionAndIncludesBlockedDrafts(t *testing.T) {
	database := newInventoryTestStore(t)
	request := inventoryPutRequest("sha256:"+strings.Repeat("e", 64), inventory.DraftBlocked)
	request.DraftID = "draft-export-blocked"
	request.Draft.Findings = []inventory.Finding{{Code: "MISSING_REFERENCE", Severity: "error", Blocking: true, RecordKind: "node", RecordID: "node-a", FieldPath: "assetId", Location: "records/node-a/assetId", RelatedIDs: []inventory.LocalID{}}}
	request.Draft.Counts.Findings = 1
	syncInventoryAuditRequest(&request)
	created, err := NewInventoryDraftRepository(database).Put(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	repository := NewInventoryExportRepository(database)
	got, err := repository.SnapshotInventoryDraft(context.Background(), created.Ref)
	if err != nil {
		t.Fatal(err)
	}
	if got.StateRevision != 1 || got.RecoveryEpoch != 0 || got.Draft.Ref != created.Ref || got.Draft.ValidationStatus != inventory.DraftBlocked || got.Draft.Kind != "draft" {
		t.Fatalf("snapshot = %#v", got)
	}
}

func TestExportAuditIsOperationalAndPendingQueryFindsOnlyUnmatchedRequest(t *testing.T) {
	database := openAuditTestStore(t)
	repository := NewInventoryExportRepository(database)
	before := readRevisionAndSequence(t, database)
	requested := exportAuditRequest("1", "inventory.export.requested", nil)
	created, err := repository.AppendExportAudit(context.Background(), requested)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := repository.PendingExportRequests(context.Background(), 64)
	if err != nil || len(pending) != 1 || pending[0].EventID != created.EventID || pending[0].Draft != (inventory.DraftRef{ID: "draft-export-1", Revision: 3}) || pending[0].ExportID != "sha256:"+strings.Repeat("a", 64) {
		t.Fatalf("pending = %#v, %v", pending, err)
	}
	after := readRevisionAndSequence(t, database)
	if after.StateRevision != before.StateRevision || after.AuditSequence != before.AuditSequence+1 {
		t.Fatalf("before/after = %#v / %#v", before, after)
	}
	terminal := exportAuditRequest("2", "inventory.export.interrupted", &created.EventID)
	terminal.Event.CorrelationID = requested.Event.CorrelationID
	terminal.Event.Target = requested.Event.Target
	terminal.Event.Before = requested.Event.Before
	terminal.Event.After = requested.Event.After
	terminal.ExpectedStateRevision = created.StateRevision
	terminal.ExpectedRecoveryEpoch = created.RecoveryEpoch
	if _, err := repository.AppendExportAudit(context.Background(), terminal); err != nil {
		t.Fatal(err)
	}
	pending, err = repository.PendingExportRequests(context.Background(), 64)
	if err != nil || len(pending) != 0 {
		t.Fatalf("terminal pending = %#v, %v", pending, err)
	}
}

func TestExportAuditRejectsMismatchedTerminalAndBounds(t *testing.T) {
	database := openAuditTestStore(t)
	repository := NewInventoryExportRepository(database)
	requested, err := repository.AppendExportAudit(context.Background(), exportAuditRequest("3", "inventory.export.requested", nil))
	if err != nil {
		t.Fatal(err)
	}
	wrong := exportAuditRequest("4", "inventory.export.published", &requested.EventID)
	wrong.Event.Target.ID = "other-draft"
	if _, err := repository.AppendExportAudit(context.Background(), wrong); err == nil {
		t.Fatal("mismatched terminal event accepted")
	}
	for _, limit := range []int{0, 65} {
		if _, err := repository.PendingExportRequests(context.Background(), limit); err == nil {
			t.Fatalf("pending limit %d accepted", limit)
		}
	}
}

func exportAuditRequest(fill, eventType string, causation *audit.EventID) stateexport.AuditAppendRequest {
	return stateexport.AuditAppendRequest{
		ExpectedStateRevision: 0,
		ExpectedRecoveryEpoch: 0,
		Idempotency: audit.IntentKey{
			Scope:         "inventory-export-" + fill,
			KeyDigest:     audit.Fingerprint("sha256:" + strings.Repeat(fill, 64)),
			RequestDigest: audit.Fingerprint("sha256:" + strings.Repeat(fill, 64)),
		},
		Event: audit.EventDraft{
			Type: audit.EventType(eventType), CorrelationID: "request-export-" + fill, CausationID: causation,
			Attribution: audit.Attribution{AuthenticatedPrincipalID: "principal-test-1", AuthenticatedPrincipalMethod: "local-os-peer"},
			Target:      audit.Target{Kind: "inventory-draft-export-r3", ID: "draft-export-1"},
			After:       fingerprintPointer("a"),
		},
	}
}

func fingerprintPointer(fill string) *audit.Fingerprint {
	value := audit.Fingerprint("sha256:" + strings.Repeat(fill, 64))
	return &value
}
