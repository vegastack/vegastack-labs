package stateexport

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/inventory"
	"github.com/vegastack/vegastack-labs/internal/result"
)

func TestExportIsDeterministicVerifiedAndAuditedWithoutChangingState(t *testing.T) {
	service, auditStore, artifacts := newStateExportTestService(t, fixedTestSigner(t), fixedTestVerifier(t))
	ctx := identity.WithVerifiedPrincipal(context.Background(), identity.Principal{ID: "principal-test-1", Method: identity.LocalOSPeerMethod})
	request := Request{CorrelationID: "request-test-1", IdempotencyKey: "export-test-1", Draft: inventory.DraftRef{ID: "draft-test-1", Revision: 1}}
	first, err := service.Export(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := service.Export(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.CanonicalBytes, retry.CanonicalBytes) || first.ContentDigest != retry.ContentDigest || first.VerificationStatus != VerificationVerified || first.PublicationStatus != "published" {
		t.Fatalf("first/retry = %#v / %#v", first, retry)
	}
	if got := auditStore.eventTypes(); got != "inventory.export.requested,inventory.export.published" {
		t.Fatalf("events = %s", got)
	}
	if artifacts.publishCalls != 2 || artifacts.current == nil || artifacts.current.ContentDigest != first.ContentDigest || first.StateRevision != 7 {
		t.Fatalf("artifacts/result = %#v / %#v", artifacts, first)
	}
}

func TestMissingProductionTrustBlocksBeforeArtifactStore(t *testing.T) {
	service, auditStore, artifacts := newStateExportTestService(t, nil, nil)
	ctx := identity.WithVerifiedPrincipal(context.Background(), identity.Principal{ID: "principal-test-1", Method: identity.LocalOSPeerMethod})
	_, err := service.Export(ctx, Request{CorrelationID: "request-test-2", IdempotencyKey: "export-test-2", Draft: inventory.DraftRef{ID: "draft-test-1", Revision: 1}})
	if codeOf(err) != "PREREQUISITE_BLOCKED" || artifacts.calls != 0 {
		t.Fatalf("result = %v, artifact calls = %d", err, artifacts.calls)
	}
	if got := auditStore.eventTypes(); got != "inventory.export.requested,inventory.export.failed" {
		t.Fatalf("events = %s", got)
	}
}

func TestExportRejectsIdentityAndVerificationFailuresWithoutPublishing(t *testing.T) {
	service, auditStore, artifacts := newStateExportTestService(t, fixedTestSigner(t), wrongTestVerifier(t))
	request := Request{CorrelationID: "request-test-3", IdempotencyKey: "export-test-3", Draft: inventory.DraftRef{ID: "draft-test-1", Revision: 1}}
	if _, err := service.Export(context.Background(), request); codeOf(err) != "AUTHENTICATION_REQUIRED" {
		t.Fatalf("missing identity = %v", err)
	}
	ctx := identity.WithVerifiedPrincipal(context.Background(), identity.Principal{ID: "principal-test-1", Method: identity.LocalOSPeerMethod})
	if _, err := service.Export(ctx, request); codeOf(err) != "INTEGRITY_FAILURE" {
		t.Fatalf("wrong verifier = %v", err)
	}
	if artifacts.publishCalls != 0 || auditStore.eventTypes() != "inventory.export.requested,inventory.export.failed" {
		t.Fatalf("artifacts/events = %d / %s", artifacts.publishCalls, auditStore.eventTypes())
	}
}

func TestReconcileRestoresPriorPointerAndRecordsInterrupted(t *testing.T) {
	payload := publicPayloadFixture(t)
	priorDocument, priorBytes := signedDocumentForPayload(t, payload)
	payload.StateRevision++
	replacementDocument, replacementBytes := signedDocumentForPayload(t, payload)
	artifacts := newMemoryArtifacts()
	prior := memoryPublish(t, artifacts, priorDocument, priorBytes)
	_ = memoryPublish(t, artifacts, replacementDocument, replacementBytes)
	previous := audit.Fingerprint(prior.Current.ArtifactID)
	requested := audit.Fingerprint(replacementDocument.ContentDigest)
	auditStore := newMemoryAudit()
	auditStore.pending = []PendingExportRequest{{
		EventID: 1, CorrelationID: "request-reconcile-1", Attribution: audit.Attribution{AuthenticatedPrincipalID: "principal-test-1", AuthenticatedPrincipalMethod: identity.LocalOSPeerMethod},
		ExportID: string(requested), Draft: inventory.DraftRef{ID: "draft-test-1", Revision: 1}, StateRevision: 7, RecoveryEpoch: 2,
		PreviousDigest: &previous, RequestedDigest: requested,
	}}
	service, err := NewService(Config{Source: &memorySnapshotSource{snapshot: DraftSnapshot{}}, Audit: auditStore, Artifacts: artifacts, Verifier: fixedTestVerifier(t), Build: result.BuildInfo{ToolVersion: "test", ReleaseBuildID: "test"}})
	if err != nil {
		t.Fatal(err)
	}
	got, err := service.Reconcile(context.Background(), 64)
	if err != nil {
		t.Fatal(err)
	}
	if got.Interrupted != 1 || artifacts.current == nil || artifacts.current.ArtifactID != prior.Current.ArtifactID || len(auditStore.pending) != 0 || auditStore.eventTypes() != "inventory.export.interrupted" {
		t.Fatalf("reconcile/current/events = %#v / %#v / %s", got, artifacts.current, auditStore.eventTypes())
	}
}

func TestTerminalAuditUncertaintyLeavesPendingForFailClosedReconciliation(t *testing.T) {
	service, auditStore, artifacts := newStateExportTestService(t, fixedTestSigner(t), fixedTestVerifier(t))
	auditStore.failType = "inventory.export.published"
	ctx := identity.WithVerifiedPrincipal(context.Background(), identity.Principal{ID: "principal-test-1", Method: identity.LocalOSPeerMethod})
	request := Request{CorrelationID: "request-terminal-uncertain", IdempotencyKey: "export-terminal-uncertain", Draft: inventory.DraftRef{ID: "draft-test-1", Revision: 1}}
	if _, err := service.Export(ctx, request); codeOf(err) != "DEPENDENCY_UNAVAILABLE" || artifacts.current == nil || len(auditStore.pending) != 1 {
		t.Fatalf("uncertain export = %v, current %#v, pending %#v", err, artifacts.current, auditStore.pending)
	}
	auditStore.failType = ""
	got, err := service.Reconcile(context.Background(), 64)
	if err != nil || got.Interrupted != 1 || artifacts.current != nil || len(auditStore.pending) != 0 {
		t.Fatalf("reconcile = %#v, %v; current %#v pending %#v", got, err, artifacts.current, auditStore.pending)
	}
}

type memorySnapshotSource struct{ snapshot DraftSnapshot }

func (source *memorySnapshotSource) SnapshotInventoryDraft(context.Context, inventory.DraftRef) (DraftSnapshot, error) {
	return source.snapshot, nil
}

type memoryAudit struct {
	events   []audit.EventDraft
	results  map[audit.Fingerprint]AuditAppendResult
	pending  []PendingExportRequest
	nextID   audit.EventID
	failType audit.EventType
}

func newMemoryAudit() *memoryAudit {
	return &memoryAudit{results: make(map[audit.Fingerprint]AuditAppendResult), nextID: 1}
}

func (store *memoryAudit) AppendExportAudit(_ context.Context, request AuditAppendRequest) (AuditAppendResult, error) {
	if request.Event.Type == store.failType {
		return AuditAppendResult{}, errors.New("private backend diagnostic")
	}
	if resultValue, ok := store.results[request.Idempotency.KeyDigest]; ok {
		return resultValue, nil
	}
	resultValue := AuditAppendResult{EventID: store.nextID, StateRevision: request.ExpectedStateRevision, RecoveryEpoch: request.ExpectedRecoveryEpoch, Created: true}
	store.nextID++
	store.results[request.Idempotency.KeyDigest] = resultValue
	store.events = append(store.events, request.Event)
	if request.Event.Type == "inventory.export.requested" {
		revision, _ := ExportTargetRevision(request.Event.Target.Kind)
		store.pending = []PendingExportRequest{{EventID: resultValue.EventID, CorrelationID: request.Event.CorrelationID, Attribution: request.Event.Attribution, ExportID: string(*request.Event.After), Draft: inventory.DraftRef{ID: inventory.DraftID(request.Event.Target.ID), Revision: revision}, StateRevision: resultValue.StateRevision, RecoveryEpoch: resultValue.RecoveryEpoch, PreviousDigest: request.Event.Before, RequestedDigest: *request.Event.After}}
	}
	if request.Event.Type == "inventory.export.published" || request.Event.Type == "inventory.export.failed" || request.Event.Type == "inventory.export.interrupted" {
		store.pending = nil
	}
	return resultValue, nil
}

func (store *memoryAudit) PendingExportRequests(context.Context, int) ([]PendingExportRequest, error) {
	return slices.Clone(store.pending), nil
}

func (store *memoryAudit) eventTypes() string {
	values := make([]string, len(store.events))
	for index := range store.events {
		values[index] = string(store.events[index].Type)
	}
	return strings.Join(values, ",")
}

type memoryArtifacts struct {
	current      *CurrentPointer
	artifacts    map[string][]byte
	calls        int
	publishCalls int
}

func newMemoryArtifacts() *memoryArtifacts {
	return &memoryArtifacts{artifacts: make(map[string][]byte)}
}

func (store *memoryArtifacts) InspectCurrent(context.Context) (*CurrentPointer, error) {
	store.calls++
	return clonePointerForTest(store.current), nil
}

func (store *memoryArtifacts) Publish(_ context.Context, request PublishRequest) (Publication, error) {
	store.calls++
	store.publishCalls++
	previous := clonePointerForTest(store.current)
	_, exists := store.artifacts[request.ArtifactID]
	store.artifacts[request.ArtifactID] = slices.Clone(request.Bytes)
	store.current = &CurrentPointer{Schema: PointerSchema, SchemaVersion: SchemaVersion, ExportKind: ExportKind, ArtifactID: request.ArtifactID, ContentDigest: request.ContentDigest}
	return Publication{Current: *store.current, Previous: previous, Created: !exists}, nil
}

func (store *memoryArtifacts) ReadArtifact(_ context.Context, artifactID string) ([]byte, error) {
	store.calls++
	raw, ok := store.artifacts[artifactID]
	if !ok {
		return nil, errors.New("missing")
	}
	return slices.Clone(raw), nil
}

func (store *memoryArtifacts) RestoreCurrent(_ context.Context, expected CurrentPointer, previous *CurrentPointer) error {
	store.calls++
	if store.current == nil || *store.current != expected {
		return errors.New("conflict")
	}
	store.current = clonePointerForTest(previous)
	return nil
}

func newStateExportTestService(t *testing.T, signer Signer, verifier Verifier) (*Service, *memoryAudit, *memoryArtifacts) {
	t.Helper()
	payload := publicPayloadFixture(t)
	auditStore := newMemoryAudit()
	artifacts := newMemoryArtifacts()
	service, err := NewService(Config{
		Source: &memorySnapshotSource{snapshot: DraftSnapshot{StateRevision: payload.StateRevision, RecoveryEpoch: payload.RecoveryEpoch, Draft: payload.Draft}},
		Audit:  auditStore, Artifacts: artifacts, Signer: signer, Verifier: verifier,
		Build: result.BuildInfo{ToolVersion: payload.ToolVersion, ReleaseBuildID: payload.ReleaseBuildID, SourceRevision: payload.SourceRevision},
	})
	if err != nil {
		t.Fatal(err)
	}
	return service, auditStore, artifacts
}

func signedDocumentForPayload(t *testing.T, payload Payload) (SignedExport, []byte) {
	t.Helper()
	_, digest, err := CanonicalPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := fixedTestSigner(t).Sign(context.Background(), SignRequest{Purpose: SigningPurpose, Digest: digest})
	if err != nil {
		t.Fatal(err)
	}
	document := SignedExport{Schema: SignedExportSchema, SchemaVersion: SchemaVersion, Payload: payload, ContentDigest: digestString(digest), Signature: signature, VerificationStatus: VerificationVerified}
	raw, _, err := CanonicalSignedExport(document)
	if err != nil {
		t.Fatal(err)
	}
	return document, raw
}

func memoryPublish(t *testing.T, artifacts *memoryArtifacts, document SignedExport, raw []byte) Publication {
	t.Helper()
	digest := sha256.Sum256(raw)
	publication, err := artifacts.Publish(context.Background(), PublishRequest{ArtifactID: "sha256:" + hex.EncodeToString(digest[:]), ContentDigest: document.ContentDigest, Bytes: raw})
	if err != nil {
		t.Fatal(err)
	}
	return publication
}

func clonePointerForTest(pointer *CurrentPointer) *CurrentPointer {
	if pointer == nil {
		return nil
	}
	copy := *pointer
	return &copy
}

func codeOf(err error) string {
	stable, ok := failure.As(err)
	if !ok {
		return ""
	}
	return stable.Code
}
