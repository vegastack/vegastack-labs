package localapi

import (
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/schedule"
)

func TestExactScheduleTargetDigestMatchesServerAuthority(t *testing.T) {
	policy := generated.ScheduledJobPolicy{
		ExactSourceIDs:  []string{"source-b", "source-a"},
		ExactSubjectIDs: []string{"subject-a"},
		ExactTargetIDs:  []string{"target-a", "target-b"},
	}
	want, err := schedule.ExactTargetDigest(policy)
	if err != nil {
		t.Fatal(err)
	}
	if got := exactScheduleTargetDigest(policy); got != want {
		t.Fatalf("digest=%q want=%q", got, want)
	}
}
