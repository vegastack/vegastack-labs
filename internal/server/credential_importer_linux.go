//go:build linux

package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/vegastack/vegastack-labs/internal/adapter/nativecredential"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type credentialCiphertextStager interface {
	Inspect(context.Context, string) (nativecredential.CiphertextInspection, error)
	Stage(context.Context, []byte, string) (string, error)
}

type nativeEncryptedDraftStager struct {
	root     string
	ownerUID uint32
}

func (stager nativeEncryptedDraftStager) Inspect(ctx context.Context, name string) (nativecredential.CiphertextInspection, error) {
	return nativecredential.InspectEncrypted(ctx, nativecredential.InspectRequest{Name: name, CiphertextDirectory: stager.root, ExpectedUID: stager.ownerUID})
}

func (stager nativeEncryptedDraftStager) Stage(ctx context.Context, private []byte, name string) (string, error) {
	return nativecredential.StageEncrypted(ctx, bytes.NewReader(private), nativecredential.StageRequest{Name: name, CiphertextDirectory: stager.root, ExpectedUID: stager.ownerUID})
}

type credentialImporter struct {
	references *store.CredentialRepository
	revisions  *store.PlanRepository
	stager     credentialCiphertextStager
	mu         sync.Mutex
}

type credentialImportService interface {
	Preflight(context.Context, generated.CredentialImportRequest, identity.Principal) (*generated.CredentialImportSubmission, error)
	Import(context.Context, generated.CredentialImportRequest, []byte, identity.Principal) (generated.CredentialImportSubmission, error)
}

func newCredentialImporter(references *store.CredentialRepository, revisions *store.PlanRepository, stager credentialCiphertextStager) *credentialImporter {
	return &credentialImporter{references: references, revisions: revisions, stager: stager}
}

func newProductionCredentialImporter(references *store.CredentialRepository, revisions *store.PlanRepository, databasePath string, ownerUID uint32) credentialImportService {
	return newCredentialImporter(references, revisions, nativeEncryptedDraftStager{root: filepath.Join(filepath.Dir(databasePath), "credential-drafts"), ownerUID: ownerUID})
}

type credentialImportBinding struct {
	name, draftID, keyDigest, requestDigest string
}

func credentialImportPublicDigest(parts ...string) string {
	hash := sha256.New()
	for _, part := range parts {
		_, _ = hash.Write([]byte(part))
		_, _ = hash.Write([]byte{0})
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}

func bindCredentialImport(input generated.CredentialImportRequest) (credentialImportBinding, error) {
	metadata, err := json.Marshal(input)
	if err != nil || generated.ValidateContractJSON(generated.SchemaIDCredentialImportRequest, metadata, generated.ContractExact) != nil || input.ResolverID != "native-systemd" || input.TargetDigest == "" || input.TargetDigest != credentialref.ImportTargetDigest(input) {
		return credentialImportBinding{}, failure.New(generated.ErrorCodeInputInvalid, "credential-import-contract", false)
	}
	name := nativecredential.LoadedNameForVersion(input.ConsumerID, input.ReferenceID, input.MaterialVersion)
	if name == "" {
		return credentialImportBinding{}, failure.New(generated.ErrorCodeInputInvalid, "credential-import-name", false)
	}
	keyDigest := credentialImportPublicDigest("credential-import-key-v1", input.IdempotencyKey, strconv.FormatInt(input.RecoveryEpoch, 10))
	requestDigest := credentialImportPublicDigest("credential-import-request-v1", string(metadata))
	return credentialImportBinding{name: name, draftID: "draft-" + requestDigest[7:39], keyDigest: keyDigest, requestDigest: requestDigest}, nil
}

func (importer *credentialImporter) Preflight(ctx context.Context, input generated.CredentialImportRequest, principal identity.Principal) (*generated.CredentialImportSubmission, error) {
	if ctx == nil || importer == nil || principal.Method != identity.LocalOSPeerMethod || principal.ID == "" {
		return nil, failure.New(generated.ErrorCodeAuthorizationDenied, "credential-import-principal", false)
	}
	if importer.references == nil || importer.revisions == nil || importer.stager == nil {
		return nil, failure.New(generated.ErrorCodePrerequisiteBlocked, "credential-import-composition", false)
	}
	binding, err := bindCredentialImport(input)
	if err != nil {
		return nil, err
	}
	token, err := importer.revisions.CurrentRevision(ctx)
	if err != nil {
		return nil, err
	}
	if token.RecoveryEpoch != input.RecoveryEpoch {
		return nil, failure.New(generated.ErrorCodePlanStale, "credential-import-epoch", false)
	}
	draft, lookupErr := importer.references.LookupImportDraft(ctx, store.CredentialImportLookup{KeyDigest: binding.keyDigest, RecoveryEpoch: input.RecoveryEpoch})
	inspection, inspectErr := importer.stager.Inspect(ctx, binding.name)
	if inspectErr != nil {
		if lookupErr == nil || store.Code(lookupErr) != generated.ErrorCodeResourceNotFound {
			return nil, failure.New(generated.ErrorCodeRecoveryRequired, "credential-import-ciphertext", false)
		}
		if ctx.Err() != nil {
			return nil, failure.New(generated.ErrorCodeInterrupted, "credential-import-ciphertext", false)
		}
		if stable, ok := failure.As(inspectErr); ok && (stable.Code == generated.ErrorCodePrerequisiteBlocked || stable.Code == generated.ErrorCodeAuthorizationDenied) {
			return nil, failure.New(stable.Code, "credential-import-ciphertext", false)
		}
		return nil, failure.New(generated.ErrorCodeRecoveryRequired, "credential-import-ciphertext", false)
	}
	if lookupErr == nil {
		if inspection.State != "present" || draft.DraftID != binding.draftID || draft.ReferenceID != input.ReferenceID || draft.ConsumerID != input.ConsumerID || draft.PurposeID != input.PurposeID || draft.TargetID != input.TargetID || draft.ResolverID != input.ResolverID || draft.MaterialVersion != input.MaterialVersion || draft.KeyDigest != binding.keyDigest || draft.RequestDigest != binding.requestDigest || draft.TargetDigest != input.TargetDigest || draft.CiphertextName != binding.name || draft.CiphertextFingerprint != inspection.Fingerprint || draft.RecoveryEpoch != input.RecoveryEpoch || token.StateRevision < draft.StateRevision {
			return nil, failure.New(generated.ErrorCodeRecoveryRequired, "credential-import-mismatch", false)
		}
		value := generated.CredentialImportSubmission{Schema: generated.SchemaIDCredentialImportSubmission, SchemaVersion: "1.1.0", DraftID: draft.DraftID, ReferenceID: draft.ReferenceID, CiphertextFingerprint: draft.CiphertextFingerprint, Status: "draft", StateRevision: draft.StateRevision, RecoveryEpoch: draft.RecoveryEpoch}
		return &value, nil
	}
	if store.Code(lookupErr) != generated.ErrorCodeResourceNotFound {
		return nil, failure.New(generated.ErrorCodeRecoveryRequired, "credential-import-metadata", false)
	}
	if inspection.State != "absent" {
		return nil, failure.New(generated.ErrorCodeRecoveryRequired, "credential-import-orphan", false)
	}
	if token.StateRevision != input.ExpectedStateRevision {
		return nil, failure.New(generated.ErrorCodePlanStale, "credential-import-revision", false)
	}
	return nil, nil
}

func (importer *credentialImporter) Import(ctx context.Context, input generated.CredentialImportRequest, private []byte, principal identity.Principal) (value generated.CredentialImportSubmission, err error) {
	defer wipeCredentialImport(private)
	defer func() {
		if recover() != nil {
			value = generated.CredentialImportSubmission{}
			err = failure.New(generated.ErrorCodeRecoveryRequired, "credential-import-indeterminate", false)
		}
	}()
	if len(private) < 8 || len(private) > 4096 {
		return value, failure.New(generated.ErrorCodeInputInvalid, "credential-input", false)
	}
	importer.mu.Lock()
	defer importer.mu.Unlock()
	existing, err := importer.Preflight(ctx, input, principal)
	if err != nil {
		return value, err
	}
	if existing != nil {
		return *existing, nil
	}
	binding, err := bindCredentialImport(input)
	if err != nil {
		return value, err
	}
	fingerprint, err := importer.stager.Stage(ctx, private, binding.name)
	if err != nil {
		if existing, retryErr := importer.Preflight(ctx, input, principal); retryErr == nil && existing != nil {
			return *existing, nil
		}
		return value, failure.New(generated.ErrorCodeRecoveryRequired, "credential-import-stage", false)
	}
	human := principal.ID
	request := store.CredentialImportDraftRequest{Input: input, DraftID: binding.draftID, CiphertextName: binding.name, CiphertextFingerprint: fingerprint, Expected: store.RevisionToken{StateRevision: input.ExpectedStateRevision, RecoveryEpoch: input.RecoveryEpoch}, Attribution: audit.Attribution{AuthenticatedPrincipalID: principal.ID, AuthenticatedPrincipalMethod: principal.Method, ResponsibleHumanPrincipalID: &human}, KeyDigest: binding.keyDigest, RequestDigest: binding.requestDigest}
	value, err = importer.references.PutImportDraft(ctx, request)
	if err != nil {
		return generated.CredentialImportSubmission{}, failure.New(generated.ErrorCodeRecoveryRequired, "credential-import-unrecorded", false)
	}
	return value, nil
}

func wipeCredentialImport(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
