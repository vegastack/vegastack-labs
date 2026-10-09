package debianbaseline

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"strings"
	"testing"
)

type fixtureReader map[ReadRequest][]byte

func (f fixtureReader) Read(_ context.Context, r ReadRequest) ([]byte, error) {
	b, ok := f[r]
	if !ok {
		return nil, errBaseline
	}
	return b, nil
}
func TestAuditRejectsArgumentCapture(t *testing.T) {
	r := fixtureReader{{Operation: ReadAuditStatus}: []byte("enabled 1\nrate_limit 1000\nbacklog_limit 8192\nlost 0\nbacklog 0\n"), {Operation: ReadAuditRules}: []byte("-a always,exit -S execve\n")}
	m, e := CollectAudit(context.Background(), generated.DebianBaselineInput{AuditPaths: []string{"/etc/passwd"}}, r)
	if e == nil && m.Status == "passed" {
		t.Fatal("argument capture passed")
	}
}
func TestAppArmorComplainCannotPass(t *testing.T) {
	r := fixtureReader{{Operation: ReadAppArmor}: []byte(`{"profiles":{"synthetic":"complain"},"processes":{}}`)}
	m, e := CollectAppArmor(context.Background(), generated.DebianBaselineInput{AppArmorProfiles: []generated.BaselineApparmorProfile{{ProfileID: "synthetic"}}}, r)
	if e == nil && m.Status == "passed" {
		t.Fatal("complain profile passed")
	}
}

func TestAuditRequiresActiveBoundedNativeState(t *testing.T) {
	in := generated.DebianBaselineInput{AuditPaths: []string{"/etc/passwd"}}
	cfg := []byte("write_logs = yes\nlocal_events = yes\nlog_file = /var/log/audit/audit.log\nlog_format = RAW\nflush = INCREMENTAL_ASYNC\nfreq = 50\nmax_log_file = 80\nnum_logs = 5\nmax_log_file_action = ROTATE\nspace_left_action = SYSLOG\nadmin_space_left_action = SYSLOG\ndisk_full_action = SYSLOG\ndisk_error_action = SYSLOG\n")
	r := fixtureReader{{Operation: ReadAuditStatus}: []byte("enabled 1\npid 100\nfailure 1\nrate_limit 1000\nbacklog_limit 8192\nlost 0\nbacklog 0\n"), {Operation: ReadAuditRules}: []byte("-w /etc/passwd -p wa -k vsk-security\n"), {Operation: ReadConfig, Selector: "auditd"}: cfg}
	m, e := CollectAudit(context.Background(), in, r)
	if e != nil || m.Status != "passed" {
		t.Fatal(m, e)
	}
	for _, status := range []string{"enabled 2\npid 100\nlost 0\n", "enabled 1\npid 0\nlost 0\n", "enabled 1\npid 100\nlost 1\n"} {
		r[ReadRequest{Operation: ReadAuditStatus}] = []byte(status)
		m, e = CollectAudit(context.Background(), in, r)
		if e == nil && m.Status == "passed" {
			t.Fatal("unsafe audit state passed")
		}
	}
}
func TestCollectorRetainsMissingRequiredControls(t *testing.T) {
	in := generated.DebianBaselineInput{ControlIDs: []string{"linux.audit-bounded", "linux.apparmor-enforcing"}}
	rows, e := Collect(context.Background(), in, fixtureReader{})
	if e != nil || len(rows) != 2 {
		t.Fatal(rows, e)
	}
	for _, m := range rows {
		if m.Status != "partial" || m.Baseline.Verification != "unavailable" || m.Baseline.NativeQualificationDigest != "" {
			t.Fatal("missing control silently qualified")
		}
	}
}
func TestTimeRejectsNaNAndLargeOffsets(t *testing.T) {
	in := generated.DebianBaselineInput{TimeOwner: "systemd-timesyncd"}
	for _, v := range []string{"NaN", "+Inf", "6", "-6"} {
		r := fixtureReader{{Operation: ReadTime, Selector: "systemd-timesyncd"}: []byte("NTPSynchronized=yes\nOffsetSeconds=" + v + "\n")}
		m, e := collectHealthControl(context.Background(), in, r, "linux.time-sync")
		if e == nil && m.Status == "passed" {
			t.Fatal("bad offset passed", v)
		}
	}
	r := fixtureReader{{Operation: ReadTime, Selector: "systemd-timesyncd"}: []byte("NTPSynchronized=yes\nOffsetSeconds=0.002\n")}
	m, e := collectHealthControl(context.Background(), in, r, "linux.time-sync")
	if e != nil || m.Status != "passed" {
		t.Fatal(m, e)
	}
}

func TestFail2banRequiresExactObservedSourcesAndBounds(t *testing.T) {
	in := generated.DebianBaselineInput{ControlIDs: []string{"linux.fail2ban-sshd"}, RecoverySourcePrefixes: []string{"192.0.2.1/32"}}
	r := fixtureReader{}
	for k, v := range map[string]string{"status": "Status\nNumber of jail: 1\nJail list: sshd", "maxretry": "5", "findtime": "600", "bantime": "600", "ignoreip": "192.0.2.1/32", "ignorecommand": "", "journalmatch": "['_SYSTEMD_UNIT=ssh.service']", "actions": "vsk-sshd", "usedns": "no"} {
		r[ReadRequest{Operation: ReadFail2ban, Selector: k}] = []byte(v)
	}
	files := DesiredFiles(in)
	r[ReadRequest{Operation: ReadConfig, Selector: "fail2ban-jail"}] = files["etc/fail2ban/jail.d/70-vsk-sshd.local"]
	r[ReadRequest{Operation: ReadConfig, Selector: "fail2ban-action"}] = files["etc/fail2ban/action.d/vsk-sshd.conf"]
	m, e := CollectFail2ban(context.Background(), in, r)
	if e != nil || m.Status != "passed" {
		t.Fatal(m, e)
	}
	for key, value := range map[string]string{"bantime": "-1", "maxretry": "50", "ignoreip": "192.0.2.1/32 attacker.example", "journalmatch": "_SYSTEMD_UNIT=ssh.service+SYSLOG_IDENTIFIER=sshd", "actions": "iptables-allports"} {
		old := r[ReadRequest{Operation: ReadFail2ban, Selector: key}]
		r[ReadRequest{Operation: ReadFail2ban, Selector: key}] = []byte(value)
		m, e = CollectFail2ban(context.Background(), in, r)
		if e == nil && m.Status == "passed" {
			t.Fatal("unsafe effective setting passed", key)
		}
		r[ReadRequest{Operation: ReadFail2ban, Selector: key}] = old
	}
}

func TestAppArmorRequiresPinnedEnforcingProfile(t *testing.T) {
	profile := []byte("profile synthetic { }\n")
	in := generated.DebianBaselineInput{AppArmorProfiles: []generated.BaselineApparmorProfile{{ProfileID: "synthetic", PackageName: "apparmor-profiles", ProfileDigest: digestBytes(profile)}}}
	r := fixtureReader{{Operation: ReadAppArmor}: []byte(`{"profiles":{"synthetic":"enforce"}}`), {Operation: ReadPackageIntegrity, Selector: "apparmor-profiles"}: []byte{}, {Operation: ReadProfile, Selector: "synthetic"}: profile}
	m, e := CollectAppArmor(context.Background(), in, r)
	if e != nil || m.Status != "passed" {
		t.Fatal(m, e)
	}
	r[ReadRequest{Operation: ReadAppArmor}] = []byte(`{"profiles":{"synthetic":"complain"}}`)
	m, e = CollectAppArmor(context.Background(), in, r)
	if e == nil && m.Status == "passed" {
		t.Fatal("complain passed")
	}
	r[ReadRequest{Operation: ReadAppArmor}] = []byte(`{"profiles":{"synthetic":"enforce"}}`)
	r[ReadRequest{Operation: ReadProfile, Selector: "synthetic"}] = []byte("changed policy")
	m, e = CollectAppArmor(context.Background(), in, r)
	if e == nil && m.Status == "passed" {
		t.Fatal("changed profile passed")
	}
}

func TestAuditLoggingCannotBeDisabledOrRedirected(t *testing.T) {
	in := generated.DebianBaselineInput{ControlIDs: []string{"linux.audit-bounded"}, AuditPaths: []string{"/etc/passwd"}}
	cfg := DesiredFiles(in)["etc/audit/auditd.conf"]
	for _, change := range [][2]string{{"write_logs = yes", "write_logs = no"}, {"local_events = yes", "local_events = no"}, {"/var/log/audit/audit.log", "/dev/null"}} {
		r := fixtureReader{{Operation: ReadAuditStatus}: []byte("enabled 1\npid 100\nfailure 1\nrate_limit 1000\nbacklog_limit 8192\nlost 0\nbacklog 0\n"), {Operation: ReadAuditRules}: []byte("-w /etc/passwd -p wa -k vsk-security\n"), {Operation: ReadConfig, Selector: "auditd"}: []byte(strings.ReplaceAll(string(cfg), change[0], change[1]))}
		m, e := CollectAudit(context.Background(), in, r)
		if e == nil && m.Status == "passed" {
			t.Fatal("disabled logging passed", change)
		}
	}
}
