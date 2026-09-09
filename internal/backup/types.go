// Package backup owns immutable local recovery artifacts while the store package
// remains the only owner of SQLite connections and database contents.
package backup

import (
	"fmt"
	"io"
	"time"
)

const (
	ManifestSchema       = "vegastack-labs.dev/sqlite-snapshot-manifest"
	ManifestVersion      = "1.0.0"
	VerificationPassed   = "verified"
	DefaultPagesPerStep  = 128
	snapshotPurpose      = "pre-migration"
	failureMigration     = "migration-blocked"
	failureIntegrity     = "integrity-failure"
	failureInterrupted   = "interrupted"
	failureUnsupported   = "unsupported-platform"
	databaseFileName     = "database.sqlite"
	manifestFileName     = "manifest.json"
	snapshotIDByteLength = 16
)

// Config describes the protected local artifact root. Root is deliberately a
// server-owned path rather than a caller-selected destination.
type Config struct {
	Root        string
	ExpectedUID uint32
	Clock       func() time.Time
	Entropy     io.Reader
}

// Manifest is the complete secret-free record stored beside one immutable
// database generation. Field order is also its canonical JSON order.
type Manifest struct {
	Schema                string `json:"schema"`
	SchemaVersion         string `json:"schemaVersion"`
	SnapshotID            string `json:"snapshotId"`
	Purpose               string `json:"purpose"`
	ToolVersion           string `json:"toolVersion"`
	BuildVersion          string `json:"buildVersion"`
	SQLiteVersion         string `json:"sqliteVersion"`
	DatabaseSchemaVersion uint64 `json:"databaseSchemaVersion"`
	CatalogSHA256         string `json:"catalogSha256"`
	StateRevision         int64  `json:"stateRevision"`
	RecoveryEpoch         int64  `json:"recoveryEpoch"`
	DatabaseSHA256        string `json:"databaseSha256"`
	DatabaseSize          int64  `json:"databaseSize"`
	Verification          string `json:"verification"`
	CreatedAt             string `json:"createdAt"`
	VerifiedAt            string `json:"verifiedAt"`
}

type classifiedError string

func (err classifiedError) Error() string { return string(err) }

func migrationError() error   { return classifiedError(failureMigration) }
func integrityError() error   { return classifiedError(failureIntegrity) }
func interruptedError() error { return classifiedError(failureInterrupted) }
func unsupportedError() error { return classifiedError(failureUnsupported) }

func randomID(entropy io.Reader) (string, error) {
	buffer := make([]byte, snapshotIDByteLength)
	if _, err := io.ReadFull(entropy, buffer); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", buffer), nil
}

func classified(got, fallback error) error {
	if got != nil {
		return got
	}
	return fallback
}
