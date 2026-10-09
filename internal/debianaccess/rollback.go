package debianaccess

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"regexp"
	"strings"
	"time"
)

const rollbackDirectory = "var/lib/vsk-labs/access-rollback"
const rollbackRecordPath = rollbackDirectory + "/record.json"
const RollbackSeconds = 600

var accessName = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
var digestRE = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
var errBaselineServicesPending = errors.New("baseline service restoration pending boot completion")
var errAccess = errors.New("debian-access prerequisite or integrity check failed")

func digestBytes(b []byte) string { s := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(s[:]) }

type RollbackFile struct {
	Path          string      `json:"path"`
	Before        []byte      `json:"before"`
	BeforePresent bool        `json:"beforePresent"`
	BeforeMode    os.FileMode `json:"beforeMode"`
	AfterMode     os.FileMode `json:"afterMode"`
	AfterDigest   string      `json:"afterDigest"`
}
type BaselineProfile struct {
	File   string `json:"file"`
	Name   string `json:"name"`
	Digest string `json:"digest"`
}
type RollbackRecord struct {
	BaselineProfiles    []BaselineProfile `json:"baselineProfiles,omitempty"`
	RunID               string            `json:"runId"`
	HostID              string            `json:"hostId"`
	HostIdentityDigest  string            `json:"hostIdentityDigest"`
	PlanID              string            `json:"planId"`
	InputDigest         string            `json:"inputDigest"`
	AuthorizationDigest string            `json:"authorizationDigest"`
	BundleDigest        string            `json:"bundleDigest"`
	BootID              string            `json:"bootId"`
	ArmedAt             time.Time         `json:"armedAt"`
	Deadline            time.Time         `json:"deadline"`
	Files               []RollbackFile    `json:"files"`
	// Firewall snapshots contain only the finite owned chain, never shared tables.
	Firewall              []RollbackFirewall  `json:"firewall,omitempty"`
	State                 string              `json:"state"`
	ProbeDigest           string              `json:"probeDigest,omitempty"`
	BaselineServiceStates map[string]string   `json:"baselineServiceStates,omitempty"`
	BaselineAudit         *BaselineAuditState `json:"baselineAudit,omitempty"`
	BaselineServices      []string            `json:"baselineServices,omitempty"`
	ReconciledBootID      string              `json:"reconciledBootId,omitempty"`
}
type FirewallState struct {
	ParentPresent bool       `json:"parentPresent"`
	Present       bool       `json:"present"`
	JumpPresent   bool       `json:"jumpPresent"`
	Rules         [][]string `json:"rules"`
}
type RollbackFirewall struct {
	Family string        `json:"family"`
	Chain  string        `json:"chain"`
	Before FirewallState `json:"before"`
	After  FirewallState `json:"after"`
}

func (r RollbackRecord) Digest() string {
	r.State = ""
	r.ProbeDigest = ""
	r.ReconciledBootID = ""
	b, _ := json.Marshal(r)
	return digestBytes(b)
}
func ownedFile(path string) bool {
	return baselineOwnedFile(path) || path == "etc/vsk-labs/service_authorized_keys/root" || path == "etc/ssh/sshd_config.d/70-vsk-access.conf" || (strings.HasPrefix(path, "etc/vsk-labs/authorized_keys/") && accessName.MatchString(strings.TrimPrefix(path, "etc/vsk-labs/authorized_keys/")))
}
func validRollback(r RollbackRecord) bool {
	if r.HostID == "" || r.PlanID == "" || r.BootID == "" || len(r.BootID) > 128 || len(r.ReconciledBootID) > 128 || !digestRE.MatchString(r.HostIdentityDigest) || !digestRE.MatchString(r.InputDigest) || !digestRE.MatchString(r.AuthorizationDigest) || !digestRE.MatchString(r.BundleDigest) || r.ArmedAt.IsZero() || r.Deadline.Sub(r.ArmedAt) != 600*time.Second || (len(r.Files) == 0 && len(r.BaselineProfiles) == 0) || len(r.Files) > 40 || len(r.Firewall) > 4 {
		return false
	}
	if len(r.BaselineServices) > 0 {
		if len(r.BaselineServiceStates) != len(r.BaselineServices) {
			return false
		}
		for _, s := range r.BaselineServices {
			if r.BaselineServiceStates[s] != "active" && r.BaselineServiceStates[s] != "inactive" {
				return false
			}
			if (s == "auditd.service") != (r.BaselineAudit != nil) && s == "auditd.service" {
				return false
			}
		}
	}
	if len(r.BaselineServices) > 0 && !validBaselineServices(r.BaselineServices) {
		return false
	}
	if r.BaselineAudit != nil && (r.BaselineAudit.RateLimit < 0 || r.BaselineAudit.BacklogLimit <= 0 || r.BaselineAudit.FailureMode < 0 || r.BaselineAudit.FailureMode > 1) {
		return false
	}
	if len(r.BaselineProfiles) > 8 {
		return false
	}
	profiles := map[string]bool{}
	for _, p := range r.BaselineProfiles {
		if !validBaselineProfile(p) || profiles[p.Name] {
			return false
		}
		profiles[p.Name] = true
	}
	seen := map[string]bool{}
	for _, f := range r.Files {
		if !ownedFile(f.Path) || seen[f.Path] || len(f.Before) > 32768 || !digestRE.MatchString(f.AfterDigest) || (f.AfterMode != 0600 && f.AfterMode != 0644) || f.BeforeMode&^0777 != 0 || f.BeforeMode&0022 != 0 || (!f.BeforePresent && len(f.Before) != 0) {
			return false
		}
		if baselineOwnedFile(f.Path) != (len(r.BaselineServices) > 0) {
			return false
		}
		seen[f.Path] = true
	}
	firewallSeen := map[string]bool{}
	for _, fw := range r.Firewall {
		if (fw.Family != "ipv4" && fw.Family != "ipv6") || (fw.Chain != "VSK-ACCESS-IN" && fw.Chain != "VSK-ACCESS-DKR") || firewallSeen[fw.Family+fw.Chain] {
			return false
		}
		firewallSeen[fw.Family+fw.Chain] = true
		for _, state := range []FirewallState{fw.Before, fw.After} {
			if len(state.Rules) > 4096 || (!state.ParentPresent && (state.Present || state.JumpPresent || len(state.Rules) > 0)) || (!state.Present && (state.JumpPresent || len(state.Rules) > 0)) {
				return false
			}
			for _, rule := range state.Rules {
				if !validOwnedRule(rule) {
					return false
				}
			}
		}
	}

	return r.State == "armed" || r.State == "confirmed" || r.State == "restored" || r.State == "uncertain" || r.State == "services-pending"
}
