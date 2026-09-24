//go:build linux

package backup

import (
	"strings"
	"testing"
	"time"
)

func TestOffsiteCustodySessionBindsGenerationAndRepository(t *testing.T) {
	now := time.Date(2026, 9, 23, 0, 0, 0, 0, time.UTC)
	lease := WriterLease{PlanID: "plan", PlanDigest: "digest", RunID: "run", StepID: "step", LeaseID: "lease", RepositoryID: "generation-a", RepositoryClass: "critical-offsite", PointID: "point", SourceRevision: 7, RecoveryEpoch: 3, MaximumExpiresAt: now.Add(time.Minute)}
	session := CustodySession{ProtocolVersion: CustodyProtocolVersion, Role: "offsite-writer", PlanID: lease.PlanID, PlanDigest: lease.PlanDigest, RunID: lease.RunID, StepID: lease.StepID, LeaseID: lease.LeaseID, RepositoryID: lease.RepositoryID, RepositoryClass: lease.RepositoryClass, GenerationID: "generation-a", OffsiteRepositoryURL: "s3:https://fixture.invalid/bucket/generation-a", PointID: lease.PointID, SourceID: "source", SourceRevision: lease.SourceRevision, RecoveryEpoch: lease.RecoveryEpoch, MaximumExpiresAt: lease.MaximumExpiresAt, MaximumObjects: 100, MaximumBytes: 4096, NonceDigest: custodyNonceDigest([]byte("nonce")), WriterLease: &lease}
	if !session.valid(now, 5*time.Minute) {
		t.Fatal("exact offsite custody session rejected")
	}
	verifier := session
	verifier.Role = "offsite-verifier"
	if !verifier.valid(now, 5*time.Minute) {
		t.Fatal("exact read-only offsite verifier custody session rejected")
	}
	for name, mutate := range map[string]func(*CustodySession){
		"repository": func(value *CustodySession) { value.OffsiteRepositoryURL = "s3:https://fixture.invalid/bucket/other" },
		"non-canonical-path": func(value *CustodySession) {
			value.OffsiteRepositoryURL = "s3:https://fixture.invalid/bucket/other/../generation-a"
		},
		"encoded-generation": func(value *CustodySession) {
			value.OffsiteRepositoryURL = "s3:https://fixture.invalid/bucket/generation%2Da"
		},
		"generation": func(value *CustodySession) { value.GenerationID = "" },
		"class":      func(value *CustodySession) { value.RepositoryClass = "critical" },
	} {
		t.Run(name, func(t *testing.T) {
			altered := session
			mutate(&altered)
			if altered.valid(now, 5*time.Minute) {
				t.Fatal("altered offsite custody session accepted")
			}
		})
	}
}

func TestParseOffsiteRepositoryIDRequiresV2ExactJSON(t *testing.T) {
	id := strings.Repeat("a", 64)
	if got, err := parseOffsiteRepositoryID([]byte(`{"version":2,"id":"` + id + `"}`)); err != nil || got != id {
		t.Fatalf("valid config = %q, %v", got, err)
	}
	for _, body := range []string{`{"version":1,"id":"` + id + `"}`, `{"version":2,"id":"short"}`, `{"version":2,"id":"` + id + `"}{}`} {
		if _, err := parseOffsiteRepositoryID([]byte(body)); err == nil {
			t.Fatalf("invalid config accepted: %s", body)
		}
	}
}

func TestSealedBearerFileHasExactLinuxSeals(t *testing.T) {
	file, err := SealedBearerFile([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if !exactSealedBearerFile(file) {
		t.Fatal("bearer descriptor not exactly sealed")
	}
}
