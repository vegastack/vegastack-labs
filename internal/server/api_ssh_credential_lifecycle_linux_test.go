//go:build linux

package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/api"
	"github.com/vegastack/vegastack-labs/internal/apissh"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/change"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/localtransport"
	"github.com/vegastack/vegastack-labs/internal/store"
)

func lifecycleSSHTestDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func TestAPISSHCredentialLifecycleFramePersistsOnlyInertMetadata(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "control.db")
	clock := func() time.Time { return time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC) }
	authority, err := store.Open(ctx, store.Config{DatabasePath: path, Mode: store.InitializeNew, ExpectedUID: uint32(os.Geteuid()), ToolVersion: "test", BuildVersion: "test", Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = authority.Close() })
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`INSERT INTO effective_authorization_principals(principal_id,principal_kind,status,grant_revision,created_at,updated_at) VALUES(?,'human','active',1,'2026-09-21T12:00:00Z','2026-09-21T12:00:00Z')`, apiSSHPrincipalID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO effective_authorization_grants(grant_id,principal_id,role_id,action,capability,resource_kind,resource_id,branch,grant_revision,status,created_at,updated_at) VALUES('grant-ssh-lifecycle-author',?,'author','author','credential.lifecycle.author','credential-reference','reference-lifecycle',NULL,1,'active','2026-09-21T12:00:00Z','2026-09-21T12:00:00Z')`, apiSSHPrincipalID); err != nil {
		t.Fatal(err)
	}
	references := store.NewCredentialRepository(authority)
	revisions := store.NewPlanRepository(authority)
	principal := identity.Principal{ID: apiSSHPrincipalID, Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman}
	importInput := generated.CredentialImportRequest{Schema: generated.SchemaIDCredentialImportRequest, SchemaVersion: "1.1.0", ReferenceID: "reference-lifecycle", ConsumerID: "consumer-lifecycle", PurposeID: "purpose-lifecycle", TargetID: "target-lifecycle", ResolverID: "native-systemd", MaterialVersion: "version-1", ExpectedStateRevision: 0, RecoveryEpoch: 0, IdempotencyKey: "import-lifecycle"}
	importInput.TargetDigest = credentialref.ImportTargetDigest(importInput)
	imported, err := references.PutImportDraft(ctx, store.CredentialImportDraftRequest{Input: importInput, DraftID: "draft-version-1", CiphertextName: "ciphertext-version-1", CiphertextFingerprint: lifecycleSSHTestDigest("ciphertext"), Expected: store.RevisionToken{}, Attribution: audit.Attribution{AuthenticatedPrincipalID: principal.ID, AuthenticatedPrincipalMethod: principal.Method}, KeyDigest: lifecycleSSHTestDigest("import-key"), RequestDigest: lifecycleSSHTestDigest("import-request")})
	if err != nil {
		t.Fatal(err)
	}
	declarations, err := change.NewService(store.NewDeclarationRepository(authority), clock)
	if err != nil {
		t.Fatal(err)
	}
	service, err := api.NewCredentialLifecycleService(references, revisions, declarations, authorization.NewEvaluator(store.NewEffectiveAuthorizationRepository(authority)))
	if err != nil {
		t.Fatal(err)
	}
	current, err := revisions.CurrentRevision(ctx)
	if err != nil {
		t.Fatal(err)
	}
	request := generated.CredentialLifecycleRequest{Schema: generated.SchemaIDCredentialLifecycleRequest, SchemaVersion: "1.2.0", Action: "credential.stage", DraftID: &imported.DraftID, ReferenceID: imported.ReferenceID, ConsumerIDs: []string{"consumer-lifecycle"}, RequiredDeniedConsumerIDs: []string{}, MaterialVersion: "version-1", ResolverID: "native-systemd", TargetID: "target-lifecycle", ExpectedStateRevision: current.StateRevision, RecoveryEpoch: current.RecoveryEpoch, IdempotencyKey: "stage-lifecycle"}
	request.TargetDigest = credentialref.LifecycleTargetDigest(request)
	payload, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	handler := newAPISSHTestHandler(&apiSSHRecorder{})
	handler.forward = func(ctx context.Context, forwarded localtransport.Request) (localtransport.Response, error) {
		if forwarded.Path == "/api/v1/health" {
			return apiSSHLocalResponse(t, apiSSHEnvelope("server status", "health-lifecycle", current.RecoveryEpoch, current.StateRevision)), nil
		}
		if forwarded.Method != localtransport.MethodPost || forwarded.Path != "/api/v1/credential-lifecycle-drafts" || !bytes.Equal(forwarded.Body, payload) {
			t.Fatalf("SSH altered metadata request: %+v", forwarded)
		}
		var decoded generated.CredentialLifecycleRequest
		if err := json.Unmarshal(forwarded.Body, &decoded); err != nil {
			t.Fatal(err)
		}
		submission, err := service.CreateDraft(ctx, decoded, principal)
		if err != nil {
			return localtransport.Response{}, err
		}
		data, err := json.Marshal(submission)
		if err != nil {
			t.Fatal(err)
		}
		envelope := apiSSHEnvelope("api.v1.credential-lifecycle-drafts.create", "local-lifecycle", submission.RecoveryEpoch, submission.StateRevision)
		envelope.Changed = true
		envelope.Data = data
		return apiSSHLocalResponse(t, envelope), nil
	}
	var output bytes.Buffer
	wire := apiSSHRequestWire(t, "POST /api/v1/credential-lifecycle-drafts", []string{"credential", "stage"}, current.RecoveryEpoch, payload)
	if err := handler.Serve(ctx, bytes.NewReader(wire), &output); err != nil {
		t.Fatal(err)
	}
	response, err := apissh.ReadResponse(&output, apiSSHRequestID)
	if err != nil || response.Envelope.Command != "api.v1.credential-lifecycle-drafts.create" || len(response.Envelope.Errors) != 0 || strings.Contains(output.String(), "ciphertextFingerprint") || strings.Contains(output.String(), "ciphertext-version") {
		t.Fatalf("framed lifecycle response = %+v %v", response, err)
	}
	var submission generated.CredentialLifecycleSubmission
	if err := json.Unmarshal(response.Envelope.Data, &submission); err != nil || submission.Status != "draft" || submission.Action != "credential.stage" || submission.ReferenceID != "reference-lifecycle" {
		t.Fatalf("framed metadata submission = %+v %v", submission, err)
	}
	var bindings int
	if err := db.QueryRow(`SELECT COUNT(*) FROM credential_lifecycle_bindings`).Scan(&bindings); err != nil || bindings != 1 {
		t.Fatalf("framed request stored inert binding count=%d err=%v", bindings, err)
	}
	output.Reset()
	mismatchedWire := apiSSHRequestWire(t, "POST /api/v1/credential-lifecycle-drafts", []string{"credential", "rotate"}, current.RecoveryEpoch, payload)
	if err := handler.Serve(ctx, bytes.NewReader(mismatchedWire), &output); err != nil {
		t.Fatal(err)
	}
	mismatched, err := apissh.ReadResponse(&output, apiSSHRequestID)
	if err != nil || len(mismatched.Envelope.Errors) == 0 {
		t.Fatalf("mismatched framed action was not denied: %+v %v", mismatched, err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM credential_lifecycle_bindings`).Scan(&bindings); err != nil || bindings != 1 {
		t.Fatal("mismatched framed action changed durable bindings")
	}
	if _, ok := api.ConstrainedSSHOperation(localtransport.MethodPost, "/api/v1/credential-references/reference-lifecycle/import-stream"); ok {
		t.Fatal("private import stream became remotely available")
	}
	output.Reset()
	privateWire := apiSSHRequestWire(t, "POST /api/v1/credential-references/reference-lifecycle/import-stream", []string{"credential", "import"}, current.RecoveryEpoch, []byte("private-canary"))
	if err := handler.Serve(ctx, bytes.NewReader(privateWire), &output); err != nil {
		t.Fatal(err)
	}
	denied, err := apissh.ReadResponse(&output, apiSSHRequestID)
	if err != nil || len(denied.Envelope.Errors) == 0 || strings.Contains(output.String(), "private-canary") {
		t.Fatalf("private import stream was not denied before forwarding: %+v %v", denied, err)
	}
}
