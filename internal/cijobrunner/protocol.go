package cijobrunner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"reflect"
	"strings"
	"sync"

	"github.com/vegastack/vegastack-labs/internal/cijobguard"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/strictjson"
)

const maxFrame = 8192

type frame struct {
	Deployment       *DeploymentCommand   `json:"deployment,omitempty"`
	DeploymentCheck  *DeploymentCheck     `json:"deploymentCheck,omitempty"`
	DeploymentResult *DeploymentResult    `json:"deploymentResult,omitempty"`
	Kind             string               `json:"kind"`
	Spec             *Spec                `json:"spec,omitempty"`
	Token            []byte               `json:"token,omitempty"`
	Decision         *cijobguard.Decision `json:"decision,omitempty"`
	Event            *LifecycleEvent      `json:"event,omitempty"`
	Runner           *ConfiguredRunner    `json:"runner,omitempty"`
	Completion       *Completion          `json:"completion,omitempty"`
}

// Stream is a single sequential private session, not an authentication boundary.
// Its inherited transport must be authenticated outside the container. No raw logs.
type Stream struct {
	reader                                *bufio.Reader
	writer                                io.Writer
	mu                                    sync.Mutex
	registration, configured, held, ready bool
	sequence                              uint32
	bytes                                 int
	deploymentPrepare                     func(context.Context, DeploymentCommand) error
	deploymentConsumer                    func(context.Context, DeploymentCommand, *credentialref.Value, func(context.Context) error) (DeploymentResult, error)
	onDecision                            func()
}

func NewStream(r io.Reader, w io.Writer) *Stream {
	reader, ok := r.(*bufio.Reader)
	if !ok {
		reader = bufio.NewReaderSize(r, maxFrame+2)
	}
	return &Stream{reader: reader, writer: w}
}
func decodeFrame(ctx context.Context, raw []byte, dst any) error {
	if strictjson.Scan(ctx, raw, strictjson.Limits{MaxDepth: 8}) != nil {
		return ErrProtocol
	}
	// DisallowUnknownFields is case insensitive; enforce exact field names recursively.
	var obj any
	if json.Unmarshal(raw, &obj) != nil || !exactJSON(obj, reflect.TypeOf(dst).Elem()) {
		return ErrProtocol
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(dst) != nil {
		return ErrProtocol
	}
	f, ok := dst.(*frame)
	if ok {
		switch f.Kind {
		case "ready", "start", "registration", "configured", "held", "decision", "event", "complete", "deployment-offer", "deployment-ready", "deployment", "deployment-check", "deployment-checked", "deployment-result":
		default:
			return ErrProtocol
		}
		count := 0
		for _, v := range []bool{f.Spec != nil, len(f.Token) > 0, f.Decision != nil, f.Event != nil, f.Runner != nil, f.Completion != nil, f.Deployment != nil, f.DeploymentCheck != nil, f.DeploymentResult != nil} {
			if v {
				count++
			}
		}
		expected := 1
		if f.Kind == "deployment" {
			expected = 2
		}
		if f.Kind == "ready" || f.Kind == "held" || f.Kind == "complete" {
			expected = 0
			if f.Kind == "complete" && f.Completion != nil {
				expected = 1
			}
		}
		if count != expected {
			return ErrProtocol
		}
		if f.Kind == "start" && f.Spec == nil || f.Kind == "registration" && len(f.Token) == 0 || f.Kind == "configured" && f.Runner == nil || f.Kind == "decision" && f.Decision == nil || f.Kind == "event" && f.Event == nil || (f.Kind == "deployment-offer" && f.Deployment == nil) || f.Kind == "deployment" && (f.Deployment == nil || len(f.Token) == 0) || (f.Kind == "deployment-ready" || f.Kind == "deployment-check" || f.Kind == "deployment-checked") && f.DeploymentCheck == nil || f.Kind == "deployment-result" && f.DeploymentResult == nil {
			return ErrProtocol
		}
	}
	return nil
}
func exactJSON(v any, t reflect.Type) bool {
	if v == nil {
		return false
	}
	if t.Kind() == reflect.Pointer {
		return exactJSON(v, t.Elem())
	}
	if t.Kind() == reflect.Struct && t.PkgPath() != "time" {
		m, ok := v.(map[string]any)
		if !ok {
			return false
		}
		fields := map[string]reflect.Type{}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			name := f.Tag.Get("json")
			if j := bytes.IndexByte([]byte(name), ','); j >= 0 {
				name = name[:j]
			}
			if name == "" {
				name = f.Name
			}
			fields[name] = f.Type
			if !strings.Contains(f.Tag.Get("json"), ",omitempty") {
				if _, ok := m[name]; !ok {
					return false
				}
			}
		}
		for k, x := range m {
			ft, ok := fields[k]
			if !ok || !exactJSON(x, ft) {
				return false
			}
		}
	}
	if t.Kind() == reflect.Slice && t.Elem().Kind() != reflect.Uint8 {
		a, ok := v.([]any)
		if !ok {
			return false
		}
		for _, x := range a {
			if !exactJSON(x, t.Elem()) {
				return false
			}
		}
	}
	return true
}
func (s *Stream) read(ctx context.Context) (frame, error) {
	var f frame
	if ctx.Err() != nil {
		return f, ErrProtocol
	}
	raw, e := readSessionFrame(s.reader)
	if e != nil {
		return f, ErrProtocol
	}
	defer clear(raw)
	if decodeFrame(ctx, raw, &f) != nil || ctx.Err() != nil {
		clear(f.Token)
		return frame{}, ErrProtocol
	}
	return f, nil
}
func (s *Stream) write(ctx context.Context, f frame) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ctx.Err() != nil {
		return ErrProtocol
	}
	raw, e := json.Marshal(f)
	if e != nil || len(raw) > maxFrame {
		return ErrProtocol
	}
	defer func() { clear(raw) }()
	raw = append(raw, '\n')
	n, e := s.writer.Write(raw)
	if e != nil || n != len(raw) {
		return ErrProtocol
	}
	return nil
}
func (s *Stream) Registration(ctx context.Context) (*credentialref.Value, error) {
	if s.registration {
		return nil, ErrProtocol
	}
	s.registration = true
	if !s.ready {
		if e := s.write(ctx, frame{Kind: "ready"}); e != nil {
			return nil, e
		}
		s.ready = true
	}
	f, e := s.read(ctx)
	if e != nil || f.Kind != "registration" {
		return nil, ErrProtocol
	}
	defer clear(f.Token)
	return credentialref.NewValue(f.Token)
}
func (s *Stream) Configured(ctx context.Context, r ConfiguredRunner) error {
	if s.configured || !s.registration || !validRegistrationStage(r.Stage) {
		return ErrProtocol
	}
	s.configured = true
	return s.write(ctx, frame{Kind: "configured", Runner: &r})
}
func (s *Stream) Held(ctx context.Context) (cijobguard.Decision, error) {
	if s.held || !s.configured {
		return cijobguard.Decision{}, ErrProtocol
	}
	s.held = true
	if e := s.write(ctx, frame{Kind: "held"}); e != nil {
		return cijobguard.Decision{}, e
	}
	f, e := s.read(ctx)
	offer := ""
	if e == nil && f.Kind == "deployment-offer" {
		if f.Deployment == nil || !validDeployment(*f.Deployment) {
			return cijobguard.Decision{}, ErrProtocol
		}
		offer = hostaction.Digest(*f.Deployment)
		if s.deploymentPrepare != nil && s.deploymentPrepare(ctx, *f.Deployment) != nil {
			return cijobguard.Decision{}, ErrBlocked
		}
		if s.write(ctx, frame{Kind: "deployment-ready", DeploymentCheck: &DeploymentCheck{CommandDigest: offer}}) != nil {
			return cijobguard.Decision{}, ErrProtocol
		}
		f, e = s.read(ctx)
	}
	if e == nil && f.Kind == "deployment" {
		if offer == "" || f.Deployment == nil || hostaction.Digest(*f.Deployment) != offer {
			clear(f.Token)
			return cijobguard.Decision{}, ErrProtocol
		}
		if s.handleDeployment(ctx, f) != nil {
			return cijobguard.Decision{}, ErrBlocked
		}
		f, e = s.read(ctx)
	}
	if e != nil || f.Kind != "decision" {
		return cijobguard.Decision{}, ErrProtocol
	}
	if s.onDecision != nil {
		s.onDecision()
	}
	return *f.Decision, nil
}
func (s *Stream) Event(ctx context.Context, e LifecycleEvent) error {
	if !validEvent(e) || e.Sequence != s.sequence+1 || s.bytes >= 1<<20 {
		return ErrProtocol
	}
	s.sequence = e.Sequence
	s.bytes += 64
	return s.write(ctx, frame{Kind: "event", Event: &e})
}

// Message contains only fixed lifecycle metadata, never raw runner output.
type Completion struct {
	Succeeded      bool   `json:"succeeded"`
	LogDigest      string `json:"logDigest"`
	Stopped        bool   `json:"stopped"`
	VolumesRemoved bool   `json:"volumesRemoved"`
}
type Message struct {
	DeploymentCheck  *DeploymentCheck
	DeploymentResult *DeploymentResult
	Kind             string
	Runner           *ConfiguredRunner
	Event            *LifecycleEvent
	Completion       *Completion
}

// Control is the controller end of the authenticated CI-only duplex exchange.
// It does not authorize admission; caller must observe/match and consume its lease.
type Control struct {
	deploymentSent                                         bool
	deploymentReady                                        bool
	deploymentDigest                                       string
	deploymentSequence                                     uint32
	deploymentResult                                       bool
	stream                                                 *Stream
	ready, registered, configured, held, decided, complete bool
	configuredOK                                           bool
	sequence                                               uint32
}

func NewControl(input io.Reader, output io.Writer) *Control {
	return &Control{stream: NewStream(input, output)}
}
func (c *Control) Receive(ctx context.Context) (Message, error) {
	f, e := c.stream.read(ctx)
	if e != nil || c.complete {
		return Message{}, ErrProtocol
	}
	switch f.Kind {
	case "ready":
		if c.ready {
			return Message{}, ErrProtocol
		}
		c.ready = true
	case "configured":
		if !c.registered || c.configured || !validRegistrationStage(f.Runner.Stage) || f.Runner.Stage == "configured" && (f.Runner.RunnerID == 0 || !identifier.MatchString(f.Runner.RunnerName)) {
			return Message{}, ErrProtocol
		}
		c.configured = true
		c.configuredOK = f.Runner.Stage == "configured"
	case "held":
		if !c.configuredOK || c.held {
			return Message{}, ErrProtocol
		}
		c.held = true
	case "deployment-ready":
		if c.deploymentDigest == "" || c.deploymentReady || f.DeploymentCheck.CommandDigest != c.deploymentDigest || f.DeploymentCheck.Sequence != 0 {
			return Message{}, ErrProtocol
		}
		c.deploymentReady = true
	case "deployment-check":
		if !c.held || c.decided || !c.deploymentSent || c.deploymentDigest == "" || c.deploymentResult || f.DeploymentCheck.CommandDigest != c.deploymentDigest || f.DeploymentCheck.Sequence != c.deploymentSequence+1 || f.DeploymentCheck.Sequence > 32 {
			return Message{}, ErrProtocol
		}
		c.deploymentSequence++
	case "deployment-result":
		if !c.deploymentSent || c.deploymentDigest == "" || c.deploymentResult || c.decided || f.DeploymentResult.CommandDigest != c.deploymentDigest {
			return Message{}, ErrProtocol
		}
		c.deploymentResult = true
	case "event":
		if !validEvent(*f.Event) || f.Event.Sequence != c.sequence+1 {
			return Message{}, ErrProtocol
		}
		c.sequence = f.Event.Sequence
	case "complete":
		if f.Completion == nil || !digest.MatchString(f.Completion.LogDigest) || f.Completion.Succeeded && (!c.decided || !f.Completion.Stopped || !f.Completion.VolumesRemoved) {
			return Message{}, ErrProtocol
		}
		c.complete = true
	default:
		return Message{}, ErrProtocol
	}
	return Message{DeploymentCheck: f.DeploymentCheck, DeploymentResult: f.DeploymentResult, Kind: f.Kind, Runner: f.Runner, Event: f.Event, Completion: f.Completion}, nil
}
func (c *Control) WriteRegistration(ctx context.Context, v *credentialref.Value) error {
	if !c.ready || c.registered || v == nil || len(v.Bytes()) < 1 || len(v.Bytes()) > 4096 {
		return ErrProtocol
	}
	c.registered = true
	return c.stream.write(ctx, frame{Kind: "registration", Token: v.Bytes()})
}
func (c *Control) WriteDecision(ctx context.Context, d cijobguard.Decision) error {
	if !c.held || c.decided || c.deploymentDigest != "" && !c.deploymentResult {
		return ErrProtocol
	}
	c.decided = true
	return c.stream.write(ctx, frame{Kind: "decision", Decision: &d})
}

// LifecycleEventDigest hashes the exact fixed event framing retained outside
// the job. Workflow/runner output is never an input to this function.
func LifecycleEventDigest(events []LifecycleEvent) (string, error) {
	if len(events) > 256 {
		return "", ErrProtocol
	}
	var b bytes.Buffer
	for i, e := range events {
		if !validEvent(e) || e.Sequence != uint32(i+1) || hostaction.WriteFrame(&b, e, 4096) != nil {
			return "", ErrProtocol
		}
	}
	return hostaction.BytesDigest(b.Bytes()), nil
}

// Preserve an inherited buffered reader even when its capacity is smaller than
// one frame. Accumulate bounded fragments rather than wrapping it and stealing
// the subsequent ordinary host-action result into a private read-ahead buffer.
func readSessionFrame(reader *bufio.Reader) ([]byte, error) {
	var raw []byte
	for {
		part, e := reader.ReadSlice('\n')
		if len(raw)+len(part) > maxFrame+1 {
			clear(raw)
			return nil, ErrProtocol
		}
		raw = append(raw, part...)
		if e == bufio.ErrBufferFull {
			continue
		}
		if e != nil || len(raw) < 2 || raw[len(raw)-1] != '\n' {
			clear(raw)
			return nil, ErrProtocol
		}
		return raw[:len(raw)-1], nil
	}
}
