package foundation

import "testing"

func TestDevelopmentIssue(t *testing.T) {
	t.Parallel()

	if DevelopmentIssue != "0.2" {
		t.Fatalf("DevelopmentIssue = %q, want %q", DevelopmentIssue, "0.2")
	}
}
