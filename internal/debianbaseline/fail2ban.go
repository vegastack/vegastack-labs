package debianbaseline

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"net/netip"
	"reflect"
	"sort"
	"strings"
)

func CollectFail2ban(ctx context.Context, in generated.DebianBaselineInput, r NativeReader) (ControlMeasurement, error) {
	c := ControlMeasurement{ControlID: "linux.fail2ban-sshd", Status: "failed", Reason: "sshd-jail-mismatch"}
	facts := map[string]string{}
	for selector, p := range map[string]string{"fail2ban-jail": "etc/fail2ban/jail.d/70-vsk-sshd.local", "fail2ban-action": "etc/fail2ban/action.d/vsk-sshd.conf"} {
		raw, e := r.Read(ctx, ReadRequest{Operation: ReadConfig, Selector: selector})
		if e != nil {
			return c, e
		}
		if digestBytes(raw) != digestBytes(DesiredFiles(in)[p]) {
			return c, nil
		}
	}

	for _, q := range []string{"status", "maxretry", "findtime", "bantime", "ignoreip", "ignorecommand", "journalmatch", "actions", "usedns"} {
		b, e := r.Read(ctx, ReadRequest{Operation: ReadFail2ban, Selector: q})
		if e != nil {
			return c, e
		}
		facts[q] = strings.TrimSpace(string(b))
	}
	for k, want := range map[string]string{"maxretry": "5", "findtime": "600", "bantime": "600", "usedns": "no", "ignorecommand": ""} {
		if facts[k] != want {
			return c, nil
		}
	}
	// Only the selected SSH jail, with trusted systemd journal attribution.
	if !strings.HasSuffix(facts["status"], "Jail list:\tsshd") && !strings.HasSuffix(facts["status"], "Jail list: sshd") {
		return c, nil
	}
	if strings.Trim(strings.TrimSpace(facts["journalmatch"]), ` []"'`) != "_SYSTEMD_UNIT=ssh.service" {
		return c, nil
	}
	if strings.TrimSpace(strings.TrimPrefix(facts["actions"], "The jail sshd has the following actions:\n")) != "vsk-sshd" {
		return c, nil
	}
	got := []string{}
	ignored := strings.TrimSpace(strings.TrimPrefix(facts["ignoreip"], "These IP addresses/networks are ignored:"))
	for _, v := range strings.FieldsFunc(ignored, func(r rune) bool {
		return r == ' ' || r == '\n' || r == '\t' || r == ',' || r == '[' || r == ']' || r == '\''
	}) {
		if v == "|-" || v == "`-" {
			continue
		}
		p, e := netip.ParsePrefix(v)
		if e == nil {
			got = append(got, p.Masked().String())
		} else if a, e := netip.ParseAddr(v); e == nil {
			got = append(got, netip.PrefixFrom(a, a.BitLen()).String())
		} else {
			return c, nil
		}
	}
	want := append([]string{}, in.RecoverySourcePrefixes...)
	sort.Strings(want)
	sort.Strings(got)
	if !reflect.DeepEqual(got, want) {
		return c, nil
	}
	c.Status = "passed"
	c.Reason = "effective-ssh-only-jail-observed"
	c.Facts = facts
	return c, nil
}
