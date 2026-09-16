//go:build linux

package store

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

func credentialImportDraftFixture() CredentialImportDraftRequest {
	input := generated.CredentialImportRequest{Schema: generated.SchemaIDCredentialImportRequest, SchemaVersion: "1.1.0", ExpectedStateRevision: 0, RecoveryEpoch: 0, IdempotencyKey: "import-a", ReferenceID: "ref-a", ConsumerID: "consumer-a", PurposeID: "deploy-a", TargetID: "service-a", ResolverID: "native-systemd", MaterialVersion: "version-a"}
	input.TargetDigest = credentialref.ImportTargetDigest(input)
	return CredentialImportDraftRequest{Input: input, DraftID: "draft-a", CiphertextName: "credential-a", CiphertextFingerprint: testDigest, Expected: RevisionToken{StateRevision: 0, RecoveryEpoch: 0}, Attribution: audit.Attribution{AuthenticatedPrincipalID: "human-a", AuthenticatedPrincipalMethod: "local-os-peer"}, KeyDigest: testDigest, RequestDigest: "sha256:" + strings.Repeat("b", 64)}
}

func TestCredentialImportDraftIsAppendOnlyInertAndIdempotent(t *testing.T) {
	repository := openCredentialStore(t)
	request := credentialImportDraftFixture()
	first, err := repository.PutImportDraft(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := repository.PutImportDraft(context.Background(), request)
	if err != nil || second != first {
		t.Fatalf("retry changed authority: %#v %v", second, err)
	}
	draft, err := repository.LookupImportDraft(context.Background(), CredentialImportLookup{KeyDigest: request.KeyDigest, RecoveryEpoch: request.Input.RecoveryEpoch})
	if err != nil || draft.DraftID != first.DraftID || draft.TargetDigest != request.Input.TargetDigest || draft.RequestDigest != request.RequestDigest {
		t.Fatalf("lookup=%#v err=%v", draft, err)
	}
	if _, err := repository.store.conn.ExecContext(context.Background(), `UPDATE credential_import_drafts SET ciphertext_fingerprint=? WHERE draft_id=?`, "sha256:"+strings.Repeat("c", 64), first.DraftID); err == nil {
		t.Fatal("append-only update accepted")
	}
	for _, table := range []string{"credential_reference_versions", "credential_step_bindings", "credential_resolution_records"} {
		var count int
		if err := repository.store.conn.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM `+table).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("draft changed %s", table)
		}
	}
}

func TestCredentialImportDraftRejectsConflictingIdempotencyAndBinding(t *testing.T) {
	repository := openCredentialStore(t)
	request := credentialImportDraftFixture()
	if _, err := repository.PutImportDraft(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	conflict := request
	conflict.DraftID = "draft-b"
	conflict.CiphertextName = "credential-b"
	conflict.CiphertextFingerprint = "sha256:" + strings.Repeat("c", 64)
	if _, err := repository.PutImportDraft(context.Background(), conflict); Code(err) != generated.ErrorCodeStateConflict {
		t.Fatalf("conflicting retry accepted: %v", err)
	}
}

func TestCredentialImportDraftConcurrentSameKeyReturnsOneSubmission(t *testing.T) {
	repository := openCredentialStore(t)
	request := credentialImportDraftFixture()
	const workers = 8
	results := make(chan generated.CredentialImportSubmission, workers)
	errors := make(chan error, workers)
	var group sync.WaitGroup
	for range workers {
		group.Add(1)
		go func() {
			defer group.Done()
			result, err := repository.PutImportDraft(context.Background(), request)
			results <- result
			errors <- err
		}()
	}
	group.Wait()
	close(results)
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatalf("concurrent retry failed: %v", err)
		}
	}
	var first generated.CredentialImportSubmission
	for result := range results {
		if first.DraftID == "" {
			first = result
			continue
		}
		if result != first {
			t.Fatalf("concurrent result changed: %#v %#v", first, result)
		}
	}
	var count int
	if err := repository.store.conn.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM credential_import_drafts`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("draft rows=%d err=%v", count, err)
	}
}
