//go:build linux || darwin

package debianaccess

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
)

func (n *nativeRuntime) armTimer(ctx context.Context, r RollbackRecord) error {
	fs, e := os.OpenRoot(n.root)
	if e != nil {
		return e
	}
	defer fs.Close()
	for p, want := range map[string][]byte{"etc/systemd/system/vsk-access-rollback.service": []byte(rollbackService), "etc/systemd/system/vsk-access-rollback-boot.service": []byte(rollbackBootService)} {
		got, _, err := readProtected(fs, p)
		if err != nil || string(got) != string(want) {
			return errAccess
		}
	}
	if e = writeAtomic(fs, "etc/systemd/system/vsk-access-rollback.timer", timerBytes(r.Deadline), 0644); e != nil {
		return e
	}
	for _, args := range [][]string{{"daemon-reload"}, {"is-enabled", "vsk-access-rollback-boot.service"}, {"restart", "vsk-access-rollback.timer"}, {"is-active", "vsk-access-rollback.timer"}} {
		if _, e = n.run(ctx, "/usr/bin/systemctl", args, nil); e != nil {
			return e
		}
	}
	return nil
}
func (n *nativeRuntime) Confirm(ctx context.Context, b generated.HostActionBundle, in generated.AccessConfirmInput) (RoleResult, error) {
	ev := b.VerificationEvidence
	if ev == nil || hostaction.Digest(*ev) != b.VerificationEvidenceDigest || in.HostID != b.HostID || in.HostIdentityDigest != b.HostIdentityDigest {
		return RoleResult{}, errAccess
	}
	expiry, e := time.Parse(time.RFC3339, ev.ExpiresAt)
	if e != nil || !n.now().Before(expiry) {
		return RoleResult{}, errAccess
	}
	var record RollbackRecord
	e = withRollback(ctx, n.root, func(fs *os.Root) error {
		r, err := readRollback(fs)
		if err != nil {
			return err
		}
		record = r
		return nil
	})
	if e != nil {
		return RoleResult{}, e
	}
	boot, e := os.ReadFile(n.root + "/proc/sys/kernel/random/boot_id")
	if e != nil || strings.TrimSpace(string(boot)) != record.BootID || record.HostID != in.HostID || record.HostIdentityDigest != in.HostIdentityDigest || record.PlanID != b.PlanID || record.RunID != b.RunID || record.InputDigest != in.ApplyInputDigest || record.AuthorizationDigest != in.RollbackDigest || record.Digest() != ev.RollbackRecordDigest {
		return RoleResult{}, errAccess
	}
	for _, fw := range record.Firewall {
		got, err := n.inspectChain(ctx, fw.Family, fw.Chain)
		if err != nil || hostaction.Digest(got) != hostaction.Digest(fw.After) {
			return RoleResult{}, errAccess
		}
	}
	if e = confirmAt(ctx, n.root, record.Digest(), b.VerificationEvidenceDigest, n.now()); e != nil {
		return RoleResult{}, e
	}
	if _, e = n.run(ctx, "/usr/bin/systemctl", []string{"stop", "vsk-access-rollback.timer"}, nil); e != nil {
		return RoleResult{}, e
	}
	m := generated.AccessMeasurement{Schema: generated.SchemaIDAccessMeasurement, SchemaVersion: "1.0.0", ControlID: "debian-access-confirm", Kind: "identity", Status: "passed", SubjectHostID: in.HostID, SubjectIdentityDigest: in.HostIdentityDigest, ProfileLockDigest: in.ProfileLockDigest, ProducerID: "debian-access-native", ProducerVersion: "1.0.0", ObservedAt: n.now().Format(time.RFC3339), ConfigurationDigest: in.ApplyInputDigest, PositiveProbeDigest: ev.ProbeResultsDigest, NegativeProbeDigest: ev.ProbeResultsDigest, Reason: "independent-probes-confirmed", RollbackRecordDigest: record.Digest()}
	return RoleResult{Changed: true, Measurements: []generated.AccessMeasurement{m}}, nil
}
func (n *nativeRuntime) ProbeSource(ctx context.Context, b generated.HostActionBundle) (RoleResult, error) {
	var in generated.AccessProbeInput
	if generated.ValidateContractJSON(generated.SchemaIDAccessProbeInput, []byte(b.ActionInput), generated.ContractExact) != nil || json.Unmarshal([]byte(b.ActionInput), &in) != nil {
		return RoleResult{}, errAccess
	}
	if in.Source.HostID != b.HostID || in.Source.IdentityDigest != b.HostIdentityDigest {
		return RoleResult{}, errAccess
	}
	m, e := ExecuteSourceProbe(ctx, in, NewNativeSourceResolver())
	return RoleResult{Measurements: m}, e
}

// RestoreNative is the finite timer/boot entry point. No caller path or command is accepted.
func RestoreNative(ctx context.Context) error {
	n := &nativeRuntime{root: "/", run: nativeCommand, now: func() time.Time { return time.Now().UTC() }}
	return n.restore(ctx)
}
func (n *nativeRuntime) restore(ctx context.Context) error {
	var record RollbackRecord
	err := withRollback(ctx, n.root, func(fs *os.Root) error {
		r, e := readRollback(fs)
		if os.IsNotExist(e) {
			return nil
		}
		record = r
		return e
	})
	if err != nil {
		return err
	}
	if record.HostID == "" {
		return nil
	}
	bootBytes, err := os.ReadFile(n.root + "/proc/sys/kernel/random/boot_id")
	if err != nil {
		return err
	}
	boot := strings.TrimSpace(string(bootBytes))
	if boot == "" {
		return errAccess
	}
	previousBoot := record.BootID
	if record.ReconciledBootID != "" {
		previousBoot = record.ReconciledBootID
	}
	newBoot := boot != previousBoot
	if record.State == "uncertain" {
		return errAccess
	}
	if record.State == "confirmed" || record.State == "restored" {
		if !newBoot {
			return nil
		}
		return withRollback(ctx, n.root, func(fs *os.Root) error {
			current, e := readRollback(fs)
			if e != nil || current.Digest() != record.Digest() || current.State != record.State {
				return errAccess
			}
			for _, f := range current.Files {
				b, mode, e := readProtected(fs, f.Path)
				if current.State == "confirmed" {
					if e != nil || digestBytes(b) != f.AfterDigest || mode != f.AfterMode {
						return errAccess
					}
				} else if !f.BeforePresent {
					if !os.IsNotExist(e) {
						return errAccess
					}
				} else if e != nil || digestBytes(b) != digestBytes(f.Before) || mode != f.BeforeMode {
					return errAccess
				}
			}
			if e = n.restoreFirewall(ctx, current, true, current.State == "confirmed"); e != nil {
				return e
			}
			current.ReconciledBootID = boot
			return saveRollback(fs, current)
		})
	}
	// Armed records restore before-state; only a new boot permits an empty kernel
	// ruleset. Repeated same-boot calls retain strict external-drift detection.
	err = restoreWith(ctx, n.root, record.Digest(), func(r RollbackRecord) error {
		if e := n.restoreFirewall(ctx, r, newBoot, false); e != nil {
			return e
		}
		if _, e := n.run(ctx, "/usr/sbin/sshd", []string{"-t"}, nil); e != nil {
			return e
		}
		if _, e := n.run(ctx, "/usr/bin/systemctl", []string{"is-active", "ssh.service"}, nil); e == nil {
			_, e = n.run(ctx, "/usr/bin/systemctl", []string{"reload", "ssh.service"}, nil)
			return e
		}
		return nil
	})
	if err != nil {
		return err
	}
	return withRollback(ctx, n.root, func(fs *os.Root) error {
		current, e := readRollback(fs)
		if e != nil || current.Digest() != record.Digest() || current.State != "restored" {
			return errAccess
		}
		current.ReconciledBootID = boot
		return saveRollback(fs, current)
	})
}

func (n *nativeRuntime) restoreFirewall(ctx context.Context, r RollbackRecord, newBoot, confirmed bool) error {
	// Validate every owned chain before any mutation. Foreign chains/rules are
	// neither flushed nor accepted as an empty kernel after reboot.
	for _, fw := range r.Firewall {
		got, e := n.inspectChain(ctx, fw.Family, fw.Chain)
		if e != nil {
			return e
		}
		d := hostaction.Digest(got)
		empty := !got.Present && !got.JumpPresent && len(got.Rules) == 0
		if d != hostaction.Digest(fw.Before) && d != hostaction.Digest(fw.After) && !(newBoot && empty) {
			return errAccess
		}
	}
	for _, fw := range r.Firewall {
		desired := fw.Before
		if confirmed {
			desired = fw.After
		}
		got, e := n.inspectChain(ctx, fw.Family, fw.Chain)
		if e != nil {
			return e
		}
		if !got.ParentPresent && desired.ParentPresent && fw.Chain == "VSK-ACCESS-DKR" {
			if !newBoot || got.Present || got.JumpPresent || len(got.Rules) != 0 {
				return errAccess
			}
			// Docker preserves user rules in this standard parent. Create only a
			// missing parent previously present in the protected record; never flush it.
			if _, e = n.run(ctx, firewallBinary(fw.Family), []string{"--wait", "5", "-N", "DOCKER-USER"}, nil); e != nil {
				return e
			}
		}
		if e = n.replaceChain(ctx, fw.Family, fw.Chain, desired); e != nil {
			return e
		}
	}
	return nil
}
