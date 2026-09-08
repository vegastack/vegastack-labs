package backup

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestManifestCanonicalRoundTripRejectsPrivateAndUnknownFields(t *testing.T) {
	m := validManifest(t)
	body, err := marshalManifest(m)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasSuffix(body, []byte("\n")) {
		t.Fatal("manifest lacks canonical newline")
	}
	for _, forbidden := range [][]byte{[]byte("/srv/control.db"), []byte("file:"), []byte("SELECT ")} {
		if bytes.Contains(body, forbidden) {
			t.Fatalf("manifest contains %q", forbidden)
		}
	}
	got, err := parseManifest(body)
	if err != nil || !reflect.DeepEqual(got, m) {
		t.Fatalf("round trip = %#v, %v", got, err)
	}

	unknown := append(bytes.TrimSuffix(body, []byte("\n"))[:len(bytes.TrimSuffix(body, []byte("\n")))-1], []byte(",\"databasePath\":\"/srv/control.db\"}\n")...)
	if _, err := parseManifest(unknown); err == nil {
		t.Fatal("unknown private field accepted")
	}
}

func TestManifestRejectsNonCanonicalAndInvalidValues(t *testing.T) {
	valid := validManifest(t)
	cases := map[string]func(*Manifest){
		"schema":       func(m *Manifest) { m.Schema = "other" },
		"version":      func(m *Manifest) { m.SchemaVersion = "2.0.0" },
		"id":           func(m *Manifest) { m.SnapshotID = "../escape" },
		"purpose":      func(m *Manifest) { m.Purpose = "scheduled" },
		"tool":         func(m *Manifest) { m.ToolVersion = "" },
		"build":        func(m *Manifest) { m.BuildVersion = "" },
		"sqlite":       func(m *Manifest) { m.SQLiteVersion = "" },
		"schemaNumber": func(m *Manifest) { m.DatabaseSchemaVersion = 0 },
		"catalog":      func(m *Manifest) { m.CatalogSHA256 = strings.Repeat("g", 64) },
		"revision":     func(m *Manifest) { m.StateRevision = -1 },
		"epoch":        func(m *Manifest) { m.RecoveryEpoch = -1 },
		"digest":       func(m *Manifest) { m.DatabaseSHA256 = "00" },
		"size":         func(m *Manifest) { m.DatabaseSize = 0 },
		"verification": func(m *Manifest) { m.Verification = "failed" },
		"createdUTC":   func(m *Manifest) { m.CreatedAt = "2026-09-08T10:00:00+05:30" },
		"verifiedUTC":  func(m *Manifest) { m.VerifiedAt = "invalid" },
		"timeOrder":    func(m *Manifest) { m.VerifiedAt = "2026-09-08T09:59:59Z" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if _, err := marshalManifest(candidate); err == nil || err.Error() != failureIntegrity {
				t.Fatalf("unsafe result: %v", err)
			}
		})
	}
}

func TestManifestRejectsDuplicateTrailingAndMissingJSON(t *testing.T) {
	m := validManifest(t)
	body, err := marshalManifest(m)
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range [][]byte{
		append(append([]byte(nil), body...), []byte("{}\n")...),
		bytes.Replace(body, []byte(`"schema":"`), []byte(`"schema":"vegastack-labs.dev/sqlite-snapshot-manifest","schema":"`), 1),
		bytes.Replace(body, []byte(`"toolVersion":"test-tool",`), nil, 1),
	} {
		if _, err := parseManifest(candidate); err == nil || err.Error() != failureIntegrity {
			t.Fatalf("unsafe result: %v", err)
		}
	}
}

func validManifest(t *testing.T) Manifest {
	t.Helper()
	created := time.Date(2026, 9, 8, 10, 0, 0, 123, time.UTC)
	return Manifest{
		Schema:                ManifestSchema,
		SchemaVersion:         ManifestVersion,
		SnapshotID:            "00112233445566778899aabbccddeeff",
		Purpose:               snapshotPurpose,
		ToolVersion:           "test-tool",
		BuildVersion:          "test-build",
		SQLiteVersion:         "3.53.4",
		DatabaseSchemaVersion: 1,
		CatalogSHA256:         strings.Repeat("a", 64),
		StateRevision:         41,
		RecoveryEpoch:         2,
		DatabaseSHA256:        strings.Repeat("b", 64),
		DatabaseSize:          4096,
		Verification:          VerificationPassed,
		CreatedAt:             created.Format(time.RFC3339Nano),
		VerifiedAt:            created.Add(time.Second).Format(time.RFC3339Nano),
	}
}
