package hostdiscovery

import (
	"slices"
	"testing"
)

func TestFindingsNeverAdmitAndPreserveMismatch(t *testing.T) {
	target := validTarget(t)
	c := Collection{Facts: Facts{Fact("os.id", "debian", "os-release"), Fact("os.version", "13", "os-release"), Fact("os.point-version", "13.6", "debian-version"), Fact("architecture", "amd64", "architecture")}}
	for _, code := range []string{"hardening-unverified", "role-admission-unverified", "missing-machine-id", "identity-class-unverified"} {
		if !slices.Contains(Findings(target, c), code) {
			t.Fatalf("missing blocker %s", code)
		}
	}
	target.ExpectedVersion = "13.6"
	if slices.Contains(Findings(target, c), "os-version-mismatch") {
		t.Fatal("point release compared against major version")
	}
	target.ExpectedVersion = "13.5"
	if !slices.Contains(Findings(target, c), "os-version-mismatch") {
		t.Fatal("point mismatch ignored")
	}
	target.ExpectedArchitecture = "arm64"
	if !slices.Contains(Findings(target, c), "architecture-mismatch") {
		t.Fatal("architecture mismatch ignored")
	}
	if c.Facts[2].Value != "13.6" {
		t.Fatal("observed fact rewritten")
	}
}
