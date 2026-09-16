package credentialref

import "testing"

func TestParseIDRejectsPathAndControlSyntax(t *testing.T) {
	for _, value := range []string{"../other-consumer", "a/b", " a", "a ", "a\\b", "a\x00b", "A"} {
		if _, err := ParseID(value); err == nil {
			t.Fatalf("unsafe logical ID accepted: %q", value)
		}
	}
	if got, err := ParseID("ref-a.2:version"); err != nil || got != Identifier("ref-a.2:version") {
		t.Fatalf("valid logical ID rejected: %q, %v", got, err)
	}
}
