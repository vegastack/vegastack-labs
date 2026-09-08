package backup

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"strings"
	"time"
)

func marshalManifest(manifest Manifest) ([]byte, error) {
	if err := validateManifest(manifest); err != nil {
		return nil, err
	}
	body, err := json.Marshal(manifest)
	if err != nil {
		return nil, integrityError()
	}
	return append(body, '\n'), nil
}

func parseManifest(body []byte) (Manifest, error) {
	if len(body) == 0 || !bytes.HasSuffix(body, []byte("\n")) {
		return Manifest{}, integrityError()
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, integrityError()
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return Manifest{}, integrityError()
	}
	if err := validateManifest(manifest); err != nil {
		return Manifest{}, err
	}
	canonical, err := marshalManifest(manifest)
	if err != nil || !bytes.Equal(canonical, body) {
		return Manifest{}, integrityError()
	}
	return manifest, nil
}

func validateManifest(manifest Manifest) error {
	if manifest.Schema != ManifestSchema ||
		manifest.SchemaVersion != ManifestVersion ||
		!validSnapshotID(manifest.SnapshotID) ||
		manifest.Purpose != snapshotPurpose ||
		!safeVersion(manifest.ToolVersion) ||
		!safeVersion(manifest.BuildVersion) ||
		!safeVersion(manifest.SQLiteVersion) ||
		manifest.DatabaseSchemaVersion == 0 ||
		!validDigest(manifest.CatalogSHA256) ||
		manifest.StateRevision < 0 ||
		manifest.RecoveryEpoch < 0 ||
		!validDigest(manifest.DatabaseSHA256) ||
		manifest.DatabaseSize <= 0 ||
		manifest.Verification != VerificationPassed {
		return integrityError()
	}
	created, createdOK := parseUTCTimestamp(manifest.CreatedAt)
	verified, verifiedOK := parseUTCTimestamp(manifest.VerifiedAt)
	if !createdOK || !verifiedOK || verified.Before(created) {
		return integrityError()
	}
	return nil
}

func validSnapshotID(value string) bool {
	if len(value) != snapshotIDByteLength*2 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == snapshotIDByteLength
}

func validDigest(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32
}

func safeVersion(value string) bool {
	if value == "" || len(value) > 128 || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}

func parseUTCTimestamp(value string) (time.Time, bool) {
	if !strings.HasSuffix(value, "Z") {
		return time.Time{}, false
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.Location() != time.UTC || parsed.Format(time.RFC3339Nano) != value {
		return time.Time{}, false
	}
	return parsed, true
}
