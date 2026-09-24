package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/result"
	"github.com/vegastack/vegastack-labs/internal/schedule"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type scheduleAPIPolicies struct{}

func (scheduleAPIPolicies) StageDraft(context.Context, generated.ScheduledJobPolicy, audit.Attribution) (store.ScheduledPolicyDraft, error) {
	return store.ScheduledPolicyDraft{}, nil
}
func (scheduleAPIPolicies) GetActivePolicy(context.Context, string) (generated.ScheduledJobPolicy, error) {
	return generated.ScheduledJobPolicy{}, nil
}
func (scheduleAPIPolicies) CurrentScheduleRevision(context.Context) (schedule.Revision, error) {
	return schedule.Revision{StateRevision: 7, RecoveryEpoch: 2}, nil
}

type scheduleAPIDispatch struct{ cancelled string }

func (*scheduleAPIDispatch) Dispatch(context.Context, schedule.DispatchRequest) (generated.ScheduledJob, error) {
	return generated.ScheduledJob{}, nil
}
func (dispatch *scheduleAPIDispatch) Cancel(_ context.Context, jobID string) (generated.ScheduledJob, error) {
	dispatch.cancelled = jobID
	return generated.ScheduledJob{Schema: generated.SchemaIDScheduledJob, SchemaVersion: "1.1.0", JobID: jobID, PolicyID: "policy-a", PolicyRevision: 1, ScheduledAt: "2026-09-24T00:00:00Z", Attempt: 1, Status: "cancelled", ReasonCode: "operator-cancelled", RecoveryEpoch: 2}, nil
}

type scheduleAPIRunner struct{}

func (scheduleAPIRunner) Run(context.Context, generated.ScheduledJob, audit.Attribution) (generated.ScheduledJob, error) {
	return generated.ScheduledJob{}, nil
}

func TestScheduledCancelAuthorizesAndRoutesExactJobID(t *testing.T) {
	requestSequence := 0
	factory := result.NewFactory(result.BuildInfo{ToolVersion: "test", ReleaseBuildID: "test"}, func() (string, error) {
		requestSequence++
		return fmt.Sprintf("request-schedule-test-%d", requestSequence), nil
	})
	app, err := NewApplication(Config{Authority: testAuthority{}, Authorizer: allowOperationAuthorizer(), Reads: testReads{}, Results: factory, Cursors: testCursor{}})
	if err != nil {
		t.Fatal(err)
	}
	recorder := &authorizationRecorderStub{}
	effective := authorization.NewEvaluator(apiPolicyRepository{snapshot: authorization.EffectivePolicySnapshot{PrincipalKind: identity.PrincipalHuman, Status: authorization.EffectiveActive, GrantRevision: 1, StateRevision: 7, RecoveryEpoch: 2, Grants: []authorization.EffectiveGrant{{Role: authorization.RoleMaintainer, AllowedAction: authorization.ActionAuthor, Capability: "schedule.dispatch", ResourceKind: "scheduled-job", ResourceID: "job-a"}}}})
	app.effective = EffectiveAuthorizationConfig{Authorizer: effective, Recorder: recorder, Clock: func() time.Time { return time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC) }}
	dispatch := &scheduleAPIDispatch{}
	if err := RegisterScheduleOperations(app, ScheduleOperations{Policies: scheduleAPIPolicies{}, Dispatch: dispatch, Runner: scheduleAPIRunner{}, Results: factory}); err != nil {
		t.Fatal(err)
	}
	input := generated.ScheduledJobCancelRequest{Schema: generated.SchemaIDScheduledJobCancelRequest, SchemaVersion: "1.1.0", IdempotencyKey: "cancel-a"}
	body, _ := json.Marshal(input)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/scheduled-jobs/job-a/cancel", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request = request.WithContext(identity.WithVerifiedPrincipal(request.Context(), identity.Principal{ID: "human-a", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman}))
	response := httptest.NewRecorder()
	app.ServeHTTP(response, request)
	if response.Code != http.StatusOK || dispatch.cancelled != "job-a" || len(recorder.records) != 1 || recorder.records[0].Decision.Target.ResourceID != "job-a" {
		t.Fatalf("status=%d cancelled=%q records=%#v body=%s", response.Code, dispatch.cancelled, recorder.records, response.Body.String())
	}
}
