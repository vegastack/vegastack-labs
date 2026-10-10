//go:build linux

package api

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

func TestNativeProfileGateAPISelectsAppliedProfileWithoutQualifyingIt(t *testing.T) {
	app, _, _, databasePath := gateAPIFixture(t)
	db, err := sql.Open("sqlite3", "file:"+databasePath+"?mode=rw")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// Synthetic scope only. No native origin, producer or qualification is seeded.
	if _, err = db.Exec(`UPDATE system_meta SET state_revision=1 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`INSERT INTO gate_applied_profiles VALUES('profile-binding','portable-profile','1.0.0','portable-policy','1.0.0',?,1,0,'profile-declaration',1,'profile-plan',?,'profile-run','profile-step','profile-lease','human-a','2026-09-15T08:00:00Z')`, []byte(`[]`), "sha256:"+strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	for _, stage := range []string{"baseline", "role", "recovery"} {
		for _, subject := range []string{"", "?subjectId=portable-profile", "?subjectId=other-profile"} {
			response := serveGateRequest(t, app, http.MethodGet, "/api/v1/gates/native."+stage+subject, nil)
			if response.Code != http.StatusOK {
				t.Fatalf("native view unavailable: %d %s", response.Code, response.Body.String())
			}
			var result generated.RunResult
			var view generated.GateView
			if json.Unmarshal(response.Body.Bytes(), &result) != nil || json.Unmarshal(result.Data, &view) != nil || view.Evaluation.Outcome == "passed" {
				t.Fatalf("scope alone qualified: %s", response.Body.String())
			}
			want := "portable-profile"
			if strings.Contains(subject, "other-profile") {
				want = "other-profile"
			}
			if view.Evaluation.SubjectID != want {
				t.Fatalf("wrong selected subject: %+v", view.Evaluation)
			}
		}
	}
}
