package audit

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

type publicCanaryFixture struct {
	ForbiddenValues []string `json:"forbiddenValues"`
	PEMHeaderParts  []string `json:"pemHeaderParts"`
}

func TestAuditValidationErrorsExcludeEveryPublicCanary(t *testing.T) {
	fixture := loadPublicCanaries(t)
	for _, canary := range fixture.ForbiddenValues {
		draft := publicFixtureEvent(t)
		draft.Type = EventType(canary)
		_, _, err := CanonicalEvent(draft)
		if err == nil {
			t.Fatalf("unsafe event type accepted")
		}
		if strings.Contains(err.Error(), canary) {
			t.Fatalf("canary leaked through validation error")
		}
	}
}

func loadPublicCanaries(t *testing.T) publicCanaryFixture {
	t.Helper()
	raw, err := os.ReadFile("testdata/public-canaries.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture publicCanaryFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.ForbiddenValues) == 0 {
		t.Fatal("public canary fixture is empty")
	}
	fixture.ForbiddenValues = append(fixture.ForbiddenValues, strings.Join(fixture.PEMHeaderParts, ""))
	return fixture
}
