// Package hostingplatform executes the finite selected Coolify component action.
package hostingplatform

import (
	"context"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/strictjson"
	"io"
	"strings"
)

const InstallAction = "hosting.platform.install"
const VerifyAction = "hosting.platform.verify"

type Input struct {
	HostID                 string `json:"hostId"`
	HostIdentityDigest     string `json:"hostIdentityDigest"`
	ComponentDirectory     string `json:"componentDirectory"`
	ComposeDigest          string `json:"composeDigest"`
	EnvironmentDigest      string `json:"environmentDigest"`
	PrivateAddress         string `json:"privateAddress"`
	ManagementPort         uint16 `json:"managementPort"`
	ControllerDatabasePath string `json:"controllerDatabasePath"`
	ControllerUnitDigest   string `json:"controllerUnitDigest"`
}
type Result struct {
	Changed bool
	Digest  string
}
type Runtime interface {
	Execute(context.Context, string, Input) (Result, error)
}
type handler struct {
	action  string
	runtime Runtime
}

func denied() error {
	return failure.New(generated.ErrorCodePrerequisiteBlocked, "hosting-platform", false)
}
func IsAction(a string) bool { return a == InstallAction || a == VerifyAction }
func NewHandler(action string, r Runtime) (hostaction.Handler, error) {
	if !IsAction(action) || r == nil {
		return nil, denied()
	}
	return handler{action, r}, nil
}
func (h handler) Execute(ctx context.Context, b generated.HostActionBundle) (generated.HostActionResult, error) {
	var out generated.HostActionResult
	if b.ActionID != h.action || b.ActionVersion != "1.0.0" || b.VerificationEvidence != nil || b.VerificationEvidenceDigest != "" {
		return out, denied()
	}
	var in Input
	dec := json.NewDecoder(strings.NewReader(b.ActionInput))
	dec.DisallowUnknownFields()
	if strictjson.Scan(ctx, []byte(b.ActionInput), strictjson.Limits{MaxDepth: 16}) != nil || dec.Decode(&in) != nil || dec.Decode(new(any)) != io.EOF || in.HostID != b.HostID || in.HostIdentityDigest != b.HostIdentityDigest {
		return out, denied()
	}
	r, e := h.runtime.Execute(ctx, h.action, in)
	if e != nil && !r.Changed {
		return out, e
	}
	bd, be := hostaction.BundleDigest(b)
	if be != nil {
		return out, be
	}
	out = generated.HostActionResult{Schema: generated.SchemaIDHostActionResult, SchemaVersion: "1.0.0", BundleDigest: bd, Status: "succeeded", Reason: "hosting-platform-observed", Changed: r.Changed, EffectObserved: true}
	if e != nil {
		out.Status = "partial"
		out.Reason = "hosting-platform-incomplete"
	}
	out.ResultDigest = hostaction.ResultDigest(out)
	return out, nil
}
func (h handler) Verify(_ context.Context, b generated.HostActionBundle, r generated.HostActionResult) error {
	bd, e := hostaction.BundleDigest(b)
	if e != nil || b.ActionID != h.action || r.BundleDigest != bd {
		return denied()
	}
	return hostaction.ValidateResult(r)
}
