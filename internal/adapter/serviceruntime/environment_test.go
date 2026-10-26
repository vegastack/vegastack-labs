package serviceruntime

import (
	"strings"
	"testing"
)

func TestEnvironmentProofReturnsOnlyHashAndRejectsChangedConsumer(t *testing.T) {
	want := EnvironmentDigest("APP_KEY", []byte("private-value"))
	calls := 0
	run := func(command string) ([]byte, error) {
		calls++
		if strings.Contains(command, "private-value") || !strings.Contains(command, "/usr/bin/sha256sum") {
			t.Fatal("plaintext in observation command")
		}
		return []byte(strings.TrimPrefix(want, "sha256:") + "  -\n"), nil
	}
	if e := verifyEnvironment([]EnvironmentFingerprint{{Name: "APP_KEY", Digest: want}}, strings.Repeat("a", 64), run); e != nil {
		t.Fatal(e)
	}
	if e := verifyEnvironment([]EnvironmentFingerprint{{Name: "APP_KEY", Digest: EnvironmentDigest("APP_KEY", []byte("changed"))}}, strings.Repeat("a", 64), run); e == nil {
		t.Fatal("wrong workload secret accepted")
	}
	if e := verifyEnvironment([]EnvironmentFingerprint{{Name: "APP_KEY;bad", Digest: want}}, strings.Repeat("a", 64), run); e == nil || calls != 2 {
		t.Fatal("unsafe name reached transport")
	}
}
