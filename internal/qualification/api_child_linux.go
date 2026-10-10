//go:build linux

package qualification

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/localapi"
	"github.com/vegastack/vegastack-labs/internal/result"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

const NativeAPIMode = "qualification-api-once"
const nativeAPIMaximum = 2 << 20

// Only already existing typed API calls cross this privilege drop. Root owns
// physical witnesses/slots; the service UID has exactly its ordinary API grants.
type nativeAPIPacket struct {
	Kind        string                                      `json:"kind"`
	Step        generated.NativeStepRequest                 `json:"step"`
	Preparation *generated.NativePreparationRequest         `json:"preparation,omitempty"`
	Collection  *generated.NativeCollectRequest             `json:"collection,omitempty"`
	Replacement *generated.NativeReplacementRecoveryRequest `json:"replacement,omitempty"`
}
type nativeAPIReply struct {
	Result  generated.NativeStepResult                  `json:"result"`
	Plan    *generated.Plan                             `json:"plan,omitempty"`
	Status  *generated.ServerStatusData                 `json:"status,omitempty"`
	Attempt *generated.NativeReplacementRecoveryAttempt `json:"attempt,omitempty"`
}
type nativeAPIBuffer struct{ bytes.Buffer }

func (b *nativeAPIBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > nativeAPIMaximum {
		return 0, ErrUnavailable
	}
	return b.Buffer.Write(p)
}

func nativeAPICommand(ctx context.Context, s generated.QualificationScope, args ...string) *exec.Cmd {
	c := exec.CommandContext(ctx, "/proc/self/exe", args...)
	c.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
	c.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL, Credential: &syscall.Credential{Uid: uint32(s.ControlServiceUID), Gid: uint32(s.ControlServiceGID), Groups: []uint32{}}}
	return c
}
func callNativeAPI(ctx context.Context, scope validatedNativeScope, in nativeAPIPacket) (nativeAPIReply, error) {
	var out nativeAPIReply
	if os.Geteuid() != 0 || scope.value.ControlServiceUID <= 0 || scope.value.ControlServiceGID <= 0 || validateAPIPacket(scope, in, time.Now().UTC()) != nil {
		return out, ErrUnavailable
	}
	raw, err := json.Marshal(in)
	if err != nil || len(raw) > nativeAPIMaximum {
		return out, ErrUnavailable
	}
	deadline, _ := time.Parse(time.RFC3339, in.Step.Deadline)
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	c := nativeAPICommand(ctx, scope.value, NativeAPIMode)
	c.Stdin = bytes.NewReader(raw)
	var output nativeAPIBuffer
	c.Stdout = &output
	c.Stderr = io.Discard
	if c.Run() != nil || fixtureDecode(ctx, output.Bytes(), &out, nativeAPIMaximum) != nil || hostaction.Digest(out.Result.Binding) != hostaction.Digest(in.Step) || !exactNativeJSON(generated.SchemaIDNativeStepResult, out.Result) {
		return nativeAPIReply{}, ErrUnavailable
	}
	return out, nil
}

func validateAPIPacket(scope validatedNativeScope, in nativeAPIPacket, now time.Time) error {
	if validateStep(scope, in.Step, now) != nil {
		return ErrUnavailable
	}
	selected := nativeAPIPacket{Kind: in.Kind, Step: in.Step}
	switch in.Kind {
	case "prepare", "fixture-plan":
		if in.Step.Operation != "prepare" || in.Preparation == nil || !exactNativeJSON(generated.SchemaIDNativePreparationRequest, *in.Preparation) || hostaction.Digest(in.Preparation.Binding) != hostaction.Digest(in.Step) || validatePreparation(scope, *in.Preparation) != nil || (in.Kind == "fixture-plan") != (in.Preparation.Kind == "fixture-approval") {
			return ErrUnavailable
		}
		selected.Preparation = in.Preparation
	case "collect-native":
		if in.Step.Operation != in.Kind || in.Collection == nil || !exactNativeJSON(generated.SchemaIDNativeCollectRequest, *in.Collection) || in.Collection.ScopeDigest != scope.digest || in.Collection.ProfileID != scope.value.ProfileID || in.Collection.RecoveryEpoch != in.Step.RecoveryEpoch {
			return ErrUnavailable
		}
		if in.Collection.HostID != "" || in.Collection.HostGateID != "" {
			match := false
			for _, g := range scope.value.Guests {
				match = match || g.HostID == in.Collection.HostID
			}
			if !match || !((in.Collection.Stage == "baseline" && (in.Collection.HostGateID == "platform-safety" || in.Collection.HostGateID == "host.hardening-baseline")) || (in.Collection.Stage == "role" && in.Collection.HostGateID == "host.role-admission")) {
				return ErrUnavailable
			}
		}
		allowed := map[string]bool{}
		for _, s := range StageScenarios(in.Collection.Stage) {
			allowed[s] = true
		}
		if !allowed[in.Step.ScenarioID] {
			return ErrUnavailable
		}
		for _, p := range in.Collection.Producers {
			if !allowed[p.ScenarioID] {
				return ErrUnavailable
			}
		}
		selected.Collection = in.Collection
	case "execute", "observe", "reboot-continuation":
		if in.Step.Operation != in.Kind {
			return ErrUnavailable
		}
	case "status":
		if in.Step.Operation != "select-controller" {
			return ErrUnavailable
		}
	case "replacement-negative":
		if in.Step.Operation != "witness" || in.Step.ScenarioID != "replacement-recovery" || in.Replacement == nil || !exactNativeJSON(generated.SchemaIDNativeReplacementRecoveryRequest, *in.Replacement) {
			return ErrUnavailable
		}
		selected.Replacement = in.Replacement
	default:
		return ErrUnavailable
	}
	if hostaction.Digest(selected) != hostaction.Digest(in) {
		return ErrUnavailable
	}
	return nil
}

func RunNativeAPIOnce(ctx context.Context, input io.Reader, output io.Writer) error {
	if os.Getuid() == 0 || os.Getuid() != os.Geteuid() || os.Getgid() != os.Getegid() {
		return ErrUnavailable
	}
	raw, err := io.ReadAll(io.LimitReader(input, nativeAPIMaximum+1))
	var in nativeAPIPacket
	if err != nil || fixtureDecode(ctx, raw, &in, nativeAPIMaximum) != nil {
		return ErrUnavailable
	}
	value, err := LoadServerScope(ctx)
	if err != nil || value.ControlServiceUID != int64(os.Geteuid()) || value.ControlServiceGID != int64(os.Getegid()) {
		return ErrUnavailable
	}
	scope, err := validateScope(value)
	if err != nil || validateAPIPacket(scope, in, time.Now().UTC()) != nil {
		return ErrUnavailable
	}
	actual, err := fileDigest("/proc/self/exe", 256<<20)
	if err != nil || actual != value.ExecutableDigest {
		return ErrUnavailable
	}
	p, err := serverconfig.NewLoader(uint32(value.ControlServiceUID)).Load(ctx, nativeClientProfilePath)
	if err != nil || validateQualificationClientProfile(p, uint32(value.ControlServiceUID)) != nil {
		return ErrUnavailable
	}
	deadline, _ := time.Parse(time.RFC3339, in.Step.Deadline)
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	source := value.SourceCommit
	c := localapi.NewClient(result.NewFactory(result.BuildInfo{ToolVersion: "native-qualification", ReleaseBuildID: value.ExecutableDigest, SourceRevision: &source}, func() (string, error) { return strings.TrimPrefix(in.Step.Nonce, "sha256:"), nil }))
	reply, err := dispatchNativeAPI(ctx, in, c, p)
	if err != nil {
		return err
	}
	raw, err = json.Marshal(reply)
	if err != nil || len(raw) > nativeAPIMaximum {
		return ErrUnavailable
	}
	_, err = output.Write(raw)
	return err
}

func dispatchNativeAPI(ctx context.Context, in nativeAPIPacket, c localapi.Client, p serverconfig.Profile) (nativeAPIReply, error) {
	out := nativeAPIReply{Result: generated.NativeStepResult{Schema: generated.SchemaIDNativeStepResult, SchemaVersion: "1.0.0", Binding: in.Step, Status: "completed", ObservationDigests: []string{}, ReceiptDigests: []string{}, ProducerRunIDs: []string{}}}
	switch in.Kind {
	case "prepare":
		r, e := dispatchPreparation(ctx, c, p, *in.Preparation)
		if e != nil {
			return out, e
		}
		out.Result.Preparation = &r
		out.Result.Changed = r.Result.Changed
	case "fixture-plan":
		r, e := c.GetPlan(ctx, p, in.Preparation.FixtureApproval.PlanID)
		if e != nil || r.ExitCode != 0 {
			return out, ErrUnavailable
		}
		current, e := c.Summary(ctx, p)
		if e != nil || current.ExitCode != 0 || current.Result.StateRevision != r.Data.Binding.StateRevision || current.Result.RecoveryEpoch != in.Step.RecoveryEpoch {
			return out, ErrUnavailable
		}
		out.Plan = &r.Data
	case "status":
		r, e := c.Status(ctx, p)
		if e != nil || r.ExitCode != 0 {
			return out, ErrUnavailable
		}
		out.Status = &r.Status
	case "replacement-negative":
		r, e := ExecuteReplacementNegative(ctx, c, p, *in.Replacement)
		if e != nil {
			return out, e
		}
		out.Attempt = &r
	case "collect-native":
		r, e := c.CollectNativeQualification(ctx, p, *in.Collection)
		if e != nil || r.ExitCode != 0 {
			return out, ErrUnavailable
		}
		out.Result.Collection = &r.Data
		out.Result.Changed = r.Result.Changed
	case "execute":
		r, e := c.ApplyBound(ctx, p, generated.PlanReferenceRequest{Schema: generated.SchemaIDPlanReferenceRequest, SchemaVersion: "1.0.0", PlanID: in.Step.PlanID, PlanDigest: in.Step.PlanDigest, RecoveryEpoch: in.Step.RecoveryEpoch, IdempotencyKey: strings.TrimPrefix(in.Step.Nonce, "sha256:"), Extensions: []generated.ContractExtension{}})
		if e != nil || r.ExitCode != 0 {
			return out, ErrUnavailable
		}
		out.Result.Run = &r.Data
		out.Result.Changed = r.Result.Changed
		out.Result.ProducerRunIDs = []string{r.Data.Run.RunID}
		out.Result.Status = "awaiting-fixture"
	case "observe", "reboot-continuation":
		r, e := c.InspectRun(ctx, p, in.Step.RunID)
		if e != nil || r.ExitCode != 0 {
			return out, ErrUnavailable
		}
		v := r.Data.Run
		if v.RunID != in.Step.RunID || v.PlanID != in.Step.PlanID || v.PlanDigest != in.Step.PlanDigest || v.RecoveryEpoch != in.Step.RecoveryEpoch {
			return out, ErrUnavailable
		}
		found := false
		for _, s := range v.Steps {
			if s.StepID == in.Step.StepID {
				found = true
			}
		}
		if !found {
			return out, ErrUnavailable
		}
		out.Result.Run = &r.Data
		out.Result.ProducerRunIDs = []string{v.RunID}
		out.Result.Status = "awaiting-fixture"
	default:
		return out, ErrUnavailable
	}
	return out, nil
}
