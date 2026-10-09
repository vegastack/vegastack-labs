package debianbaseline

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"regexp"
	"strings"
)

func digestBytes(b []byte) string { s := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(s[:]) }
func selected(in generated.DebianBaselineInput, id string) bool {
	for _, v := range in.ControlIDs {
		if v == id {
			return true
		}
	}
	return false
}
func DesiredFiles(in generated.DebianBaselineInput) map[string][]byte {
	files := map[string][]byte{}
	if selected(in, "linux.fail2ban-sshd") {
		files["etc/fail2ban/jail.d/70-vsk-sshd.local"] = []byte("[DEFAULT]\nenabled = false\n[sshd]\nenabled = true\nbackend = systemd\njournalmatch = _SYSTEMD_UNIT=ssh.service\nusedns = no\nmaxretry = 5\nfindtime = 600\nbantime = 600\nbantime.increment = false\nignorecommand =\nignoreip = " + strings.Join(in.RecoverySourcePrefixes, " ") + "\naction = vsk-sshd\n")
		files["etc/fail2ban/action.d/vsk-sshd.conf"] = []byte("[Definition]\nactionstart = <iptables> -S f2b-vsk-sshd >/dev/null 2>&1 || <iptables> -N f2b-vsk-sshd\n              <iptables> -C f2b-vsk-sshd -j RETURN >/dev/null 2>&1 || <iptables> -A f2b-vsk-sshd -j RETURN\n              <iptables> -C INPUT -p tcp --dport 22 -j f2b-vsk-sshd >/dev/null 2>&1 || <iptables> -I INPUT 1 -p tcp --dport 22 -j f2b-vsk-sshd\nactionstop = <iptables> -D INPUT -p tcp --dport 22 -j f2b-vsk-sshd\n             <iptables> -F f2b-vsk-sshd\n             <iptables> -X f2b-vsk-sshd\nactioncheck = <iptables> -C INPUT -p tcp --dport 22 -j f2b-vsk-sshd\nactionban = <iptables> -I f2b-vsk-sshd 1 -s <ip> -j DROP\nactionunban = <iptables> -D f2b-vsk-sshd -s <ip> -j DROP\n[Init]\niptables = /usr/sbin/iptables-nft -w\n[Init?family=inet6]\niptables = /usr/sbin/ip6tables-nft -w\n")
	}
	if selected(in, "linux.audit-bounded") {
		var b strings.Builder
		b.WriteString("-b 8192\n-r 1000\n-f 1\n")
		for _, p := range in.AuditPaths {
			fmt.Fprintf(&b, "-w %s -p wa -k vsk-security\n", p)
		}
		files["etc/audit/rules.d/70-vsk-security.rules"] = []byte(b.String())
		files["etc/audit/auditd.conf"] = []byte("local_events = yes\nwrite_logs = yes\nlog_file = /var/log/audit/audit.log\nlog_format = RAW\nflush = INCREMENTAL_ASYNC\nfreq = 50\nmax_log_file = 80\nnum_logs = 5\nmax_log_file_action = ROTATE\nspace_left = 100\nspace_left_action = SYSLOG\nadmin_space_left = 50\nadmin_space_left_action = SYSLOG\ndisk_full_action = SYSLOG\ndisk_error_action = SYSLOG\n")
	}
	if selected(in, "linux.aide-integrity") {
		var b strings.Builder
		b.WriteString("database_in=file:/var/lib/vsk-labs/baseline/aide.db\ndatabase_out=file:/var/lib/vsk-labs/baseline/aide.new.db\nreport_url=stdout\nreport_format=json\nVSK=p+i+n+u+g+s+m+c+sha256\n")
		for _, p := range in.AIDE.ScopePaths {
			fmt.Fprintf(&b, "=%s$ VSK\n", regexp.QuoteMeta(p))
		}
		files["etc/vsk-labs/baseline/aide.conf"] = []byte(b.String())
	}
	return files
}
func PolicyDigest(in generated.DebianBaselineInput) string {
	return hostaction.Digest(DesiredFiles(in))
}
func RenderPolicy(ctx context.Context, in generated.DebianBaselineInput) (string, error) {
	if e := ctx.Err(); e != nil {
		return "", e
	}
	return PolicyDigest(in), nil
}
