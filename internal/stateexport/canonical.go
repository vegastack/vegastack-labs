package stateexport

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"reflect"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/inventory"
)

var (
	digestPattern   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	tokenPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+:-]{0,127}$`)
	revisionPattern = regexp.MustCompile(`^[0-9a-f]{40,64}$`)
)

func CanonicalPayload(value Payload) ([]byte, [32]byte, error) {
	if err := validatePayload(value); err != nil {
		return nil, [32]byte{}, err
	}
	body, err := json.Marshal(value)
	if err != nil || len(body) == 0 || len(body) > MaxArtifactBytes {
		return nil, [32]byte{}, exportError("INPUT_INVALID", "inventory-export-payload")
	}
	return body, sha256.Sum256(body), nil
}

func CanonicalSignedExport(value SignedExport) ([]byte, [32]byte, error) {
	if value.Schema != SignedExportSchema || value.SchemaVersion != SchemaVersion ||
		!digestPattern.MatchString(value.ContentDigest) || value.VerificationStatus != VerificationVerified ||
		value.Signature.Algorithm == "" || value.Signature.KeyID == "" || value.Signature.KeyFingerprint == "" || value.Signature.Value == "" {
		return nil, [32]byte{}, exportError("INPUT_INVALID", "inventory-export-document")
	}
	if _, _, err := CanonicalPayload(value.Payload); err != nil {
		return nil, [32]byte{}, err
	}
	if err := validateStrings(reflect.ValueOf(value)); err != nil {
		return nil, [32]byte{}, err
	}
	body, err := json.Marshal(value)
	if err != nil || len(body) == 0 || len(body) > MaxArtifactBytes {
		return nil, [32]byte{}, exportError("INPUT_INVALID", "inventory-export-document")
	}
	return body, sha256.Sum256(body), nil
}

func DecodeSignedExport(raw []byte) (SignedExport, error) {
	if len(raw) == 0 || len(raw) > MaxArtifactBytes {
		return SignedExport{}, exportError("INPUT_INVALID", "inventory-export-document")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var value SignedExport
	if err := decoder.Decode(&value); err != nil {
		return SignedExport{}, exportError("INPUT_INVALID", "inventory-export-document")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return SignedExport{}, exportError("INPUT_INVALID", "inventory-export-document")
	}
	canonical, _, err := CanonicalSignedExport(value)
	if err != nil || !bytes.Equal(canonical, raw) {
		return SignedExport{}, exportError("INTEGRITY_FAILURE", "inventory-export-document")
	}
	return value, nil
}

func CanonicalPointer(value CurrentPointer) ([]byte, error) {
	if value.Schema != PointerSchema || value.SchemaVersion != SchemaVersion || value.ExportKind != ExportKind ||
		!digestPattern.MatchString(value.ArtifactID) || !digestPattern.MatchString(value.ContentDigest) {
		return nil, exportError("INPUT_INVALID", "inventory-export-pointer")
	}
	body, err := json.Marshal(value)
	if err != nil {
		return nil, exportError("INPUT_INVALID", "inventory-export-pointer")
	}
	return body, nil
}

func DecodePointer(raw []byte) (CurrentPointer, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var value CurrentPointer
	if err := decoder.Decode(&value); err != nil {
		return CurrentPointer{}, exportError("INTEGRITY_FAILURE", "inventory-export-pointer")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return CurrentPointer{}, exportError("INTEGRITY_FAILURE", "inventory-export-pointer")
	}
	canonical, err := CanonicalPointer(value)
	if err != nil || !bytes.Equal(canonical, raw) {
		return CurrentPointer{}, exportError("INTEGRITY_FAILURE", "inventory-export-pointer")
	}
	return value, nil
}

func validatePayload(value Payload) error {
	if value.Schema != PayloadSchema || value.SchemaVersion != SchemaVersion || value.ExportKind != ExportKind || value.SubjectKind != SubjectKind ||
		value.RecoveryEpoch < 0 || value.StateRevision < 0 || !tokenPattern.MatchString(value.ToolVersion) || !tokenPattern.MatchString(value.ReleaseBuildID) ||
		(value.SourceRevision != nil && !revisionPattern.MatchString(*value.SourceRevision)) || len(value.Contents) != 1 ||
		value.Contents[0] != (KindCount{Kind: "inventory-draft", Count: 1}) {
		return exportError("INPUT_INVALID", "inventory-export-payload")
	}
	if err := validateDraft(value.Draft); err != nil {
		return err
	}
	return validateStrings(reflect.ValueOf(value))
}

func validateDraft(value inventory.CanonicalDraftSnapshot) error {
	if value.Kind != SubjectKind || value.Ref.ID == "" || value.Ref.Revision < 1 ||
		(value.ValidationStatus != inventory.DraftValid && value.ValidationStatus != inventory.DraftBlocked) ||
		!digestPattern.MatchString(value.Source.Digest) || !digestPattern.MatchString(value.ContentDigest) || !canonicalUTC(value.Source.CapturedAt) ||
		value.Assets == nil || value.Nodes == nil || value.Aliases == nil || value.Addresses == nil || value.Observations == nil || value.Provenance == nil || value.Findings == nil {
		return exportError("INPUT_INVALID", "inventory-export-draft")
	}
	for _, asset := range value.Assets {
		if asset.Identities == nil || asset.HardwareFacts == nil {
			return exportError("INPUT_INVALID", "inventory-export-draft")
		}
	}
	for _, observation := range value.Observations {
		if !canonicalUTC(observation.ObservedAt) {
			return exportError("INPUT_INVALID", "inventory-export-draft")
		}
	}
	for _, provenance := range value.Provenance {
		if !canonicalUTC(provenance.CapturedAt) {
			return exportError("INPUT_INVALID", "inventory-export-draft")
		}
	}
	for _, finding := range value.Findings {
		if finding.RelatedIDs == nil {
			return exportError("INPUT_INVALID", "inventory-export-draft")
		}
	}
	return nil
}

func canonicalUTC(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Nanosecond() >= 0
}

func validateStrings(value reflect.Value) error {
	if value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return nil
		}
		return validateStrings(value.Elem())
	}
	switch value.Kind() {
	case reflect.Struct:
		for index := 0; index < value.NumField(); index++ {
			if err := validateStrings(value.Field(index)); err != nil {
				return err
			}
		}
	case reflect.Slice, reflect.Array:
		for index := 0; index < value.Len(); index++ {
			if err := validateStrings(value.Index(index)); err != nil {
				return err
			}
		}
	case reflect.String:
		text := value.String()
		if !utf8.ValidString(text) || strings.ContainsRune(text, 0) || len(text) > 4096 {
			return exportError("INPUT_INVALID", "inventory-export-string")
		}
	}
	return nil
}

func digestString(sum [32]byte) string { return "sha256:" + hex.EncodeToString(sum[:]) }

func exportError(code, target string) error { return failure.New(code, target, false) }
