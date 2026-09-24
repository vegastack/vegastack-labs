package cli

import (
	"context"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

func TestDatabaseExportHumanAndJSONStayInertAndAgree(t *testing.T) {
	operations := successfulControlOperations(t)
	request := syntheticGateRequest(t, generated.CommandNameDatabaseExport)
	base := []string{"database", "export", "--config", "profile.json", "--file", "export.json"}
	code, human, stderr := runTestAppWithOptions(t, context.Background(), base, nil, WithControlOperations(operations, &stubFileReader{content: request}))
	if code != 0 || stderr != "" || !strings.Contains(human, "Inert database export draft export-test: draft") || !strings.Contains(human, "create and authorize an exact export plan") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, human, stderr)
	}
	code, machine, stderr := runTestAppWithOptions(t, context.Background(), append(base, "--output", "json"), nil, WithControlOperations(operations, &stubFileReader{content: request}))
	if code != 0 || stderr != "" || !strings.Contains(machine, `"status":"draft"`) || strings.Contains(machine, "contentDigest") || strings.Contains(machine, "published") || strings.Contains(machine, "verified") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, machine, stderr)
	}
}

func TestDatabaseBackupHumanOutputDoesNotClaimQualification(t *testing.T) {
	operations := successfulControlOperations(t)
	code, stdout, stderr := runTestAppWithOptions(t, context.Background(), []string{"database", "backup", "--config", "profile.json", "--file", "backup.json"}, nil, WithControlOperations(operations, &stubFileReader{content: syntheticGateRequest(t, generated.CommandNameDatabaseBackup)}))
	if code != 0 || stderr != "" || !strings.Contains(stdout, "qualification still requires database verify") || strings.Contains(stdout, "verified backup") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}
