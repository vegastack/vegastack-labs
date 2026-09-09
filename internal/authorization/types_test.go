package authorization

import (
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/inventory"
)

func TestResourceIDIsCanonicalAndBounded(t *testing.T) {
	got := ResourceID(inventory.DraftRef{ID: "draft-test-1", Revision: 7})
	if got != "draft-test-1:7" {
		t.Fatalf("ResourceID = %q", got)
	}
	if ResourceID(inventory.DraftRef{ID: inventory.DraftID(strings.Repeat("a", 129)), Revision: 1}) != "" {
		t.Fatal("oversized ID accepted")
	}
}
