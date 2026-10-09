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
	if record.HostID == "" || record.State == "confirmed" || record.State == "restored" {
		return nil
	}
	// Both timer and boot invoke restoration, never confirmation. Same-boot early
	// invocation may restore safely; it cannot extend the risky configuration.
	return restoreWith(ctx, n.root, record.Digest(), func(r RollbackRecord) error {
		for _, fw := range r.Firewall {
			got, e := n.inspectChain(ctx, fw.Family, fw.Chain)
			if e != nil {
				return e
			}
			d := hostaction.Digest(got)
			if d != hostaction.Digest(fw.Before) && d != hostaction.Digest(fw.After) {
				return errAccess
			}
		}
		for _, fw := range r.Firewall {
			if e := n.replaceChain(ctx, fw.Family, fw.Chain, fw.Before); e != nil {
				return e
			}
		}
		if _, e := n.run(ctx, "/usr/sbin/sshd", []string{"-t"}, nil); e != nil {
			return e
		}
		// Boot recovery runs before ssh starts; only reload a currently active service.
		if _, e := n.run(ctx, "/usr/bin/systemctl", []string{"is-active", "ssh.service"}, nil); e == nil {
			_, e = n.run(ctx, "/usr/bin/systemctl", []string{"reload", "ssh.service"}, nil)
			return e
		}
		return nil
	})
}
