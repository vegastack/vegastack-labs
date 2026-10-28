// Package ingressconnector owns one fixed, explicitly selected cloudflared service.
package ingressconnector

import (
	"context"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/debianaccess"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/strictjson"
	"io"
	"regexp"
	"strings"
)

const Action = "cloudflare.connector.install"
const Version = "2026.10.5"
const BinarySHA256 = "e1bc0cf084fd9e590554fe769a86b1db46701c3f847a43d902f7b974a4e16298"
const BinaryPath = "/usr/local/bin/vsk-labs-cloudflared"
const UnitName = "vsk-labs-ingress.service"
const UnitPath = "/etc/systemd/system/" + UnitName
const TokenPath = "/etc/vsk-labs/ingress/tunnel-token"
const CAPath = "/etc/vsk-labs/ingress/origin-ca.pem"
const BinaryURL = "https://github.com/cloudflare/cloudflared/releases/download/" + Version + "/cloudflared-linux-amd64"

var account = regexp.MustCompile(`^[a-f0-9]{32}$`)
var uuid = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)
var digest = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

type Input struct {
	HostID             string `json:"hostId"`
	AccountID          string `json:"accountId"`
	HostIdentityDigest string `json:"hostIdentityDigest"`
	TunnelID           string `json:"tunnelId"`
	OriginCADigest     string `json:"originCaDigest,omitempty"`
}

func Decode(raw []byte) (Input, error) {
	var in Input
	d := json.NewDecoder(strings.NewReader(string(raw)))
	d.DisallowUnknownFields()
	if len(raw) > 4096 || strictjson.Scan(context.Background(), raw, strictjson.Limits{MaxDepth: 4}) != nil || d.Decode(&in) != nil || d.Decode(new(any)) != io.EOF || in.HostID == "" || debianaccess.ProtectedName(in.HostID) || !account.MatchString(in.AccountID) || !digest.MatchString(in.HostIdentityDigest) || !uuid.MatchString(in.TunnelID) || (in.OriginCADigest != "" && !digest.MatchString(in.OriginCADigest)) {
		return Input{}, denied()
	}
	return in, nil
}
func denied() error {
	return failure.New(generated.ErrorCodePrerequisiteBlocked, "ingress-connector", false)
}

type Result struct {
	Changed  bool
	Verified bool
}
type Runtime interface {
	Install(context.Context, Input) (Result, error)
}
type handler struct{ runtime Runtime }

func NewHandler(r Runtime) (hostaction.Handler, error) {
	if r == nil {
		return nil, denied()
	}
	return handler{r}, nil
}
func (h handler) Execute(ctx context.Context, b generated.HostActionBundle) (generated.HostActionResult, error) {
	var out generated.HostActionResult
	if b.ActionID != Action || b.ActionVersion != "1.0.0" || b.VerificationEvidence != nil || b.VerificationEvidenceDigest != "" {
		return out, denied()
	}
	in, e := Decode([]byte(b.ActionInput))
	if e != nil || in.HostID != b.HostID || in.HostIdentityDigest != b.HostIdentityDigest {
		return out, denied()
	}
	r, e := h.runtime.Install(ctx, in)
	if e != nil && !r.Changed {
		return out, denied()
	}
	bd, err := hostaction.BundleDigest(b)
	if err != nil {
		return out, err
	}
	out = generated.HostActionResult{Schema: generated.SchemaIDHostActionResult, SchemaVersion: "1.0.0", BundleDigest: bd, Status: "succeeded", Changed: r.Changed, EffectObserved: true, Reason: "connector-service-observed"}
	if e != nil || !r.Verified {
		out.Status = "partial"
		out.Reason = "connector-service-unverified"
	}
	out.ResultDigest = hostaction.ResultDigest(out)
	return out, nil
}
func (h handler) Verify(_ context.Context, b generated.HostActionBundle, r generated.HostActionResult) error {
	d, e := hostaction.BundleDigest(b)
	if e != nil || r.BundleDigest != d || r.ResultDigest != hostaction.ResultDigest(r) || (r.Status != "succeeded" && r.Status != "partial") {
		return denied()
	}
	return nil
}
func Unit(in Input) []byte {
	return []byte("[Unit]\nDescription=VegaStack Labs connector " + in.TunnelID + "\nAfter=network-online.target\nWants=network-online.target\n[Service]\nType=simple\nDynamicUser=yes\nLoadCredential=tunnel-token:" + TokenPath + "\nExecStart=" + BinaryPath + " --no-autoupdate tunnel run --token-file %d/tunnel-token\nRestart=on-failure\nRestartSec=5s\nStandardOutput=null\nStandardError=null\nUMask=0077\nNoNewPrivileges=yes\nPrivateTmp=yes\nProtectSystem=strict\nProtectHome=yes\n[Install]\nWantedBy=multi-user.target\n")
}
