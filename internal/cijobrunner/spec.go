// Package cijobrunner runs one finite stock runner inside rootless Docker.
// It supplies neither controller admission authority nor online host qualification.
package cijobrunner

import (
	"context"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/cijobguard"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
)

var ErrBlocked = errors.New("ci runtime blocked")
var ErrProtocol = errors.New("ci runtime protocol invalid")

const Image = "ghcr.io/actions/actions-runner@sha256:759a1d94a15b05941aba5196974ff43fe15b4cbba29b694b35cbc32a1166b232"
const PID1Mode = "ci-job-init"
const HookMode = "ci-job-hook"
const runnerRoot = "/home/runner"
const toolsRoot = "/vsk-ci"
const hookSocket = "/tmp/vsk-ci-hook.sock"
const HookScript = "#!/bin/sh\nexec /vsk-ci/vsk-labs ci-job-hook\n"

var identifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
var digest = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
var organization = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,38}$`)

type LaunchBinding struct {
	LifecycleID string `json:"lifecycleId"`
	RunID       string `json:"runId"`
	PlanID      string `json:"planId"`
	LeaseID     string `json:"leaseId"`
	Attempt     uint32 `json:"attempt"`
	Epoch       uint64 `json:"epoch"`
}
type Spec struct {
	Binding          LaunchBinding `json:"binding"`
	Deadline         time.Time     `json:"deadline"`
	RuntimeProfileID string        `json:"runtimeProfileId"`
	RuntimeDigest    string        `json:"runtimeDigest"`
	Organization     string        `json:"organization"`
	RunnerName       string        `json:"runnerName"`
	RunnerGroup      string        `json:"runnerGroup"`
	Labels           []string      `json:"labels"`
}
type RuntimeProfile struct {
	ImageIndexDigest      string
	ExecutableDigest      string
	HookDigest            string
	DNSResolver           string `json:",omitempty"`
	NetworkID             string
	NetworkEvidenceDigest string
	DaemonUID             uint32
	MemoryBytes           int64
	CPUQuotaMicros        int64
	CPUPeriodMicros       int64
	PidsLimit             int64
	Offline               bool
}

// Check must inspect the actual current protected network for this daemon/profile.
// A digest comparison or a caller's qualification Boolean cannot implement it.
type NetworkCheck struct {
	ContainerID string `json:"containerId"`
	InitPID     int    `json:"initPid"`
}

// DeploymentNetworkVerifier additionally proves this exact provider origin is
// reachable under the current protected network policy. Ordinary public-only
// qualification never implies private hosting access.
type DeploymentNetworkVerifier interface {
	CheckDeployment(context.Context, RuntimeProfile, NetworkCheck, string) error
}

type NetworkVerifier interface {
	Check(context.Context, RuntimeProfile, NetworkCheck) error
}
type LifecycleEvent struct {
	Stage    string `json:"stage"`
	Sequence uint32 `json:"sequence"`
	ExitCode int    `json:"exitCode"`
}
type ConfiguredRunner struct {
	Stage      string `json:"stage"`
	RunnerID   uint64 `json:"runnerId"`
	RunnerName string `json:"runnerName"`
}
type Session interface {
	Registration(context.Context) (*credentialref.Value, error)
	Configured(context.Context, ConfiguredRunner) error
	Held(context.Context) (cijobguard.Decision, error)
	Event(context.Context, LifecycleEvent) error
}

func validBinding(b LaunchBinding) bool {
	n, e := strconv.ParseInt(b.RunID, 10, 64)
	return identifier.MatchString(b.LifecycleID) && identifier.MatchString(b.PlanID) && identifier.MatchString(b.LeaseID) && e == nil && n > 0 && strconv.FormatInt(n, 10) == b.RunID && b.Attempt > 0
}
func validateLaunch(s Spec) error {
	if !validBinding(s.Binding) || !s.Deadline.After(time.Now()) || s.Deadline.After(time.Now().Add(time.Hour)) || !identifier.MatchString(s.RuntimeProfileID) || !digest.MatchString(s.RuntimeDigest) || !organization.MatchString(s.Organization) || !identifier.MatchString(s.RunnerName) || len(s.RunnerName) > 64 || len(s.RunnerGroup) == 0 || len(s.RunnerGroup) > 128 || len(s.Labels) == 0 || len(s.Labels) > 64 {
		return ErrBlocked
	}
	for _, c := range s.RunnerGroup {
		if c < 32 || c > 126 {
			return ErrBlocked
		}
	}
	seen := map[string]bool{}
	for _, v := range s.Labels {
		if !identifier.MatchString(v) || len(v) > 64 || seen[strings.ToLower(v)] {
			return ErrBlocked
		}
		seen[strings.ToLower(v)] = true
	}
	return nil
}
func ValidateSpec(s Spec, p RuntimeProfile) error {
	if validateLaunch(s) != nil || s.RuntimeDigest != ComputeRuntimeDigest(p) || "sha256:"+Image[len(Image)-64:] != p.ImageIndexDigest || !digest.MatchString(p.ExecutableDigest) || !digest.MatchString(p.HookDigest) || p.DaemonUID == 0 || p.MemoryBytes < 64<<20 || p.MemoryBytes > 8<<30 || p.CPUPeriodMicros < 1000 || p.CPUPeriodMicros > 1000000 || p.CPUQuotaMicros < 1000 || p.CPUQuotaMicros > p.CPUPeriodMicros*8 || p.PidsLimit < 16 || p.PidsLimit > 1024 {
		return ErrBlocked
	}
	if p.Offline {
		if p.NetworkID != "none" {
			return ErrBlocked
		}
	} else if !identifier.MatchString(p.NetworkID) || p.NetworkID == "host" || p.NetworkID == "none" || !digest.MatchString(p.NetworkEvidenceDigest) {
		return ErrBlocked
	}
	return nil
}
func ValidateDecision(b LaunchBinding, d cijobguard.Decision) error {
	n, e := strconv.ParseInt(d.Binding.JobID, 10, 64)
	if !validBinding(b) || d.Action != "allow" || e != nil || n < 1 || strconv.FormatInt(n, 10) != d.Binding.JobID || d.Binding.LifecycleID != b.LifecycleID || d.Binding.RunID != b.RunID || d.Binding.PlanID != b.PlanID || d.Binding.LeaseID != b.LeaseID || d.Binding.Attempt != b.Attempt || d.Binding.Epoch != b.Epoch {
		return ErrBlocked
	}
	return nil
}
func validEvent(e LifecycleEvent) bool {
	switch e.Stage {
	case "prepared", "started", "registration_attempted", "registration_secret_delivered", "configured", "held", "allowed", "listener_exited", "stopped", "cleaned", "failed":
		return e.Sequence > 0 && e.Sequence <= 256 && e.ExitCode >= 0 && e.ExitCode <= 255
	}
	return false
}

// ComputeRuntimeDigest binds every actual protected runtime field with existing canonical JSON hashing.
func ComputeRuntimeDigest(p RuntimeProfile) string { return hostaction.Digest(p) }

func validRegistrationStage(stage string) bool {
	return stage == "registration_attempted" || stage == "registration_secret_delivered" || stage == "configured"
}
