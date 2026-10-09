package debianbaseline

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"strings"
)

func CollectAudit(ctx context.Context, in generated.DebianBaselineInput, r NativeReader) (ControlMeasurement, error) {
	c := ControlMeasurement{ControlID: "linux.audit-bounded", Status: "failed", Reason: "audit-policy-mismatch"}
	s, e := r.Read(ctx, ReadRequest{Operation: ReadAuditStatus})
	if e != nil {
		return c, e
	}
	rules, e := r.Read(ctx, ReadRequest{Operation: ReadAuditRules})
	if e != nil {
		return c, e
	}
	status := kv(s)
	if status["enabled"] != "1" || status["lost"] != "0" || status["backlog_limit"] != "8192" || status["rate_limit"] != "1000" {
		return c, nil
	}
	pid, pidErr := number(status["pid"])
	if pidErr != nil || pid <= 0 || status["failure"] != "1" {
		return c, nil
	}
	backlog, e := number(status["backlog"])
	if e != nil || backlog < 0 || backlog >= 8192 {
		return c, nil
	}
	want := map[string]bool{}
	for _, p := range in.AuditPaths {
		want[p] = false
	}
	for _, line := range strings.Split(strings.TrimSpace(string(rules)), "\n") {
		f := strings.Fields(line)
		if len(f) != 6 || f[0] != "-w" || f[2] != "-p" || f[3] != "wa" || f[4] != "-k" || f[5] != "vsk-security" {
			return c, nil
		}
		if _, ok := want[f[1]]; !ok {
			return c, nil
		}
		want[f[1]] = true
	}
	for _, seen := range want {
		if !seen {
			return c, nil
		}
	}
	cfg, e := r.Read(ctx, ReadRequest{Operation: ReadConfig, Selector: "auditd"})
	if e != nil {
		return c, e
	}
	values := configurationValues(cfg)
	for k, v := range map[string]string{"max_log_file": "80", "num_logs": "5", "max_log_file_action": "ROTATE", "space_left_action": "SYSLOG", "admin_space_left_action": "SYSLOG", "disk_full_action": "SYSLOG", "disk_error_action": "SYSLOG"} {
		if values[k] != v {
			return c, nil
		}
	}
	c.Status = "passed"
	c.Reason = "bounded-effective-audit-observed"
	c.Facts = map[string]any{"status": status, "paths": in.AuditPaths, "config": values}
	return c, nil
}
func configurationValues(b []byte) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if ok {
			m[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return m
}
