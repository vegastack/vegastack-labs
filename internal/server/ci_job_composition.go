package server

import (
	"context"
	"encoding/json"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/adapter/githubci"
	transport "github.com/vegastack/vegastack-labs/internal/adapter/hostaction"
	"github.com/vegastack/vegastack-labs/internal/ci"
	"github.com/vegastack/vegastack-labs/internal/cijobguard"
	"github.com/vegastack/vegastack-labs/internal/cijobrunner"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type ciJobReadiness struct{ replacement hostReplacementComposition }

func (c ciJobReadiness) CheckCIJobHost(ctx context.Context, id string) (store.HostAdmissionSnapshot, error) {
	s, e := c.replacement.roleAdmission(ctx, id)
	if e != nil {
		return s, e
	}
	if s.Profile.RoleID != "ci" || s.Profile.OSFamily != "linux" && s.Profile.OSFamily != "debian" {
		return s, actionFailure()
	}
	return s, nil
}
func newCIJobRepository(s *store.Store, g *store.GateRepository) *store.CIJobRepository {
	r := store.NewCIJobRepository(s)
	r.ConfigureAdmission(g, ciJobReadiness{hostReplacementComposition{authority: s, gates: g, clock: time.Now}})
	return r
}

type ciJobExecutionSource struct {
	hosts *store.HostActionRepository
	jobs  *store.CIJobRepository
}

func (s ciJobExecutionSource) CurrentExecution(ctx context.Context, op adapter.Operation, b adapter.ExactExecutionBinding) (store.HostActionExecution, error) {
	if op.OperationType == store.CIJobOperation {
		return s.jobs.CurrentExecution(ctx, op, b)
	}
	return s.hosts.CurrentExecution(ctx, op, b)
}
func (s ciJobExecutionSource) ExecutionForBundle(ctx context.Context, b generated.HostActionBundle) (store.HostActionExecution, error) {
	if b.ActionID == store.CIJobOperation {
		return s.jobs.ExecutionForBundle(ctx, b)
	}
	return s.hosts.ExecutionForBundle(ctx, b)
}

type ciJobControlFactory struct {
	deployment *ciExternalDeploymentControl
	jobs       *store.CIJobRepository
	provider   *githubci.Client
}

func (f ciJobControlFactory) NewCIControl(ctx context.Context, op adapter.Operation, b adapter.ExactExecutionBinding, values []*credentialref.Value) (transport.CIControl, error) {
	if f.jobs == nil || f.provider == nil || len(values) != 3 || len(op.SecretReferences) != 3 {
		return nil, actionFailure()
	}
	x, e := f.jobs.CurrentExecution(ctx, op, b)
	if e != nil {
		return nil, e
	}
	expected, e := f.jobs.StepBindings(*x.Plan.CIJob)
	if e != nil {
		return nil, e
	}
	found := map[string]*credentialref.Value{}
	for _, v := range expected {
		for i, ref := range op.SecretReferences {
			if ref.ID == v.ReferenceID && ref.Consumer == hostaction.AdapterID && values[i] != nil {
				if found[v.PurposeID] != nil {
					return nil, actionFailure()
				}
				found[v.PurposeID] = values[i]
			}
		}
	}
	if len(found) != 3 {
		return nil, actionFailure()
	}
	return &ciJobControl{deployment: f.deployment, jobs: f.jobs, provider: f.provider, op: op, binding: b, request: *x.Plan.CIJob, registration: found[store.CIJobRegistrationPurpose], observer: found[store.CIJobObserverPurpose]}, nil
}

type ciJobControl struct {
	deployment             *ciExternalDeploymentControl
	jobs                   *store.CIJobRepository
	provider               *githubci.Client
	op                     adapter.Operation
	binding                adapter.ExactExecutionBinding
	request                generated.CiJobRequest
	registration, observer *credentialref.Value
	configured             *cijobrunner.ConfiguredRunner
	completion             *cijobrunner.Completion
	events                 []cijobrunner.LifecycleEvent
	spec                   cijobrunner.Spec
}

func (c *ciJobControl) check(ctx context.Context) error {
	_, e := c.jobs.CurrentExecution(ctx, c.op, c.binding)
	return e
}
func (c *ciJobControl) Exchange(ctx context.Context, b generated.HostActionBundle, reader io.Reader, input io.WriteCloser) error {
	if json.Unmarshal([]byte(b.ActionInput), &c.spec) != nil || c.spec.Binding.LifecycleID != store.CIJobLifecycleID(c.binding) || c.spec.Binding.RunID != c.request.RunID || c.spec.Binding.Attempt != uint32(c.request.Attempt) || c.spec.Binding.PlanID != c.binding.PlanID || c.spec.Binding.LeaseID != c.binding.LeaseID || c.spec.Binding.Epoch != uint64(c.binding.RecoveryEpoch) {
		return actionFailure()
	}
	if e := c.jobs.Begin(ctx, c.op, c.binding); e != nil {
		return e
	}
	control := cijobrunner.NewControl(reader, input)
	// One finite authority watcher belongs to this exact SSH lifecycle. It owns no
	// queue or retry path; revocation closes the channel and aborts the owned job.
	live, cancel := context.WithCancel(ctx)
	defer cancel()
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-live.Done():
				return
			case <-ticker.C:
				if c.check(live) != nil {
					_ = input.Close()
					cancel()
					return
				}
			}
		}
	}()
	defer func() { cancel(); <-stopped }()
	for {
		message, e := control.Receive(live)
		if e != nil || live.Err() != nil {
			return actionFailure()
		}
		switch message.Kind {
		case "ready":
			policy, e := c.jobs.Policy(live, c.binding, c.request)
			if e != nil {
				return e
			}
			p := policy.Policy
			owner, e := strconv.ParseInt(p.OwnerID, 10, 64)
			if e != nil {
				return actionFailure()
			}
			group, e := strconv.ParseInt(p.RunnerGroupID, 10, 64)
			if e != nil {
				return actionFailure()
			}
			if e = c.jobs.RecordRegistrationStage(live, c.op, c.binding, "registration_attempted"); e != nil {
				return e
			}
			_, e = c.provider.PrepareRegistration(live, githubci.RunnerRegistrationRequest{Organization: githubci.OrganizationTarget{Login: strings.Split(p.Repository, "/")[0], ID: owner}, Repository: p.Repository, RepositoryID: p.RepositoryID, RepositoryOwnerID: p.OwnerID, GroupName: c.spec.RunnerGroup, GroupID: group, Check: func() error { return c.check(live) }}, c.registration, func(tokenCtx context.Context, token *credentialref.Value, _ time.Time) error {
				if e := c.jobs.RecordRegistrationStage(tokenCtx, c.op, c.binding, "registration_input_attempted"); e != nil {
					return e
				}
				return control.WriteRegistration(tokenCtx, token)
			})
			if e != nil {
				return e
			}
		case "configured":
			if message.Runner == nil {
				return actionFailure()
			}
			if message.Runner.Stage != "configured" {
				if e = c.jobs.RecordRegistrationStage(live, c.op, c.binding, message.Runner.Stage); e != nil {
					return e
				}
				return actionFailure()
			}
			if e = c.jobs.RecordConfigured(live, c.op, c.binding, message.Runner.RunnerID, message.Runner.RunnerName); e != nil {
				return e
			}
			copy := *message.Runner
			c.configured = &copy
		case "held":
			if c.configured == nil {
				return actionFailure()
			}
			policy, e := c.jobs.Policy(live, c.binding, c.request)
			if e != nil {
				return e
			}
			p := policy.Policy
			enrollment := ci.Enrollment{ID: policy.Definition.EnrollmentID, Binding: ci.Binding{RepositoryID: p.RepositoryID, OwnerID: p.OwnerID, Repository: p.Repository, WorkflowID: p.WorkflowID, WorkflowPath: p.WorkflowPath, WorkflowDigest: p.WorkflowDigest, Revision: p.Revision, Ref: p.Ref, Event: p.Event, JobName: p.JobName, RunnerID: strconv.FormatUint(c.configured.RunnerID, 10), RunnerGroupID: p.RunnerGroupID, Labels: p.Labels}}
			observed, e := c.provider.FindAssignedJob(live, githubci.AssignmentTarget{Enrollment: enrollment, RunnerName: c.configured.RunnerName, RunnerOS: "linux", GroupName: c.spec.RunnerGroup, RunID: c.request.RunID, Attempt: uint32(c.request.Attempt), Check: func() error { return c.check(live) }}, c.observer)
			if e != nil {
				return e
			}
			if _, e = ci.Match(enrollment, observed, time.Now().UTC()); e != nil {
				return e
			}
			if e = c.jobs.ConsumeAdmission(live, c.op, c.binding, observed); e != nil {
				return e
			}
			if e = c.check(live); e != nil {
				return e
			}
			if c.request.DeploymentDigest != "" {
				if c.deployment == nil {
					return actionFailure()
				}
				if e = c.deployment.exchange(live, c, control); e != nil {
					return e
				}
			}
			decision := cijobguard.Decision{Action: "allow", Binding: cijobguard.Binding{LifecycleID: c.spec.Binding.LifecycleID, RunID: observed.RunID, JobID: observed.JobID, Attempt: observed.Attempt, PlanID: c.binding.PlanID, LeaseID: c.binding.LeaseID, Epoch: uint64(c.binding.RecoveryEpoch)}}
			if cijobrunner.ValidateDecision(c.spec.Binding, decision) != nil {
				return actionFailure()
			}
			if e = control.WriteDecision(live, decision); e != nil {
				return e
			}
		case "event":
			if message.Event == nil || len(c.events) >= 256 {
				return actionFailure()
			}
			if e = c.jobs.RecordEvent(live, c.op, c.binding, *message.Event); e != nil {
				return e
			}
			c.events = append(c.events, *message.Event)
		case "complete":
			if message.Completion == nil {
				return actionFailure()
			}
			digest, e := cijobrunner.LifecycleEventDigest(c.events)
			if e != nil || digest != message.Completion.LogDigest {
				return actionFailure()
			}
			copy := *message.Completion
			c.completion = &copy
			return nil
		default:
			return actionFailure()
		}
	}
}
func (c *ciJobControl) Finish(ctx context.Context, b generated.HostActionBundle, result generated.HostActionResult) error {
	if c.completion == nil {
		return actionFailure()
	}
	completion := *c.completion
	verified := completion.Succeeded && completion.Stopped && completion.VolumesRemoved && result.Status == "succeeded" && result.EffectObserved
	if completion.Stopped && c.configured != nil {
		policy, e := c.jobs.Policy(ctx, c.binding, c.request)
		if e != nil {
			return e
		}
		p := policy.Policy
		owner, e := strconv.ParseInt(p.OwnerID, 10, 64)
		if e != nil {
			return actionFailure()
		}
		_, e = c.provider.RemoveOwnedRunner(ctx, githubci.RunnerCleanupRequest{Organization: githubci.OrganizationTarget{Login: strings.Split(p.Repository, "/")[0], ID: owner}, RunnerID: int64(c.configured.RunnerID), Name: c.configured.RunnerName, OS: "linux", Labels: p.Labels, Check: func() error { return c.check(ctx) }}, c.registration)
		if e != nil {
			return e
		}
	} else {
		verified = false
	}
	digest := hostaction.Digest(struct {
		Completion   cijobrunner.Completion
		ResultDigest string
		Events       []cijobrunner.LifecycleEvent
	}{completion, result.ResultDigest, c.events})
	if e := c.jobs.RecordCompletion(ctx, c.op, c.binding, digest, completion.LogDigest, verified); e != nil {
		return e
	}
	if !verified {
		return actionFailure()
	}
	return nil
}
