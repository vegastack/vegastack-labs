//go:build linux

package nativecredential

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type policyCommandRunner func(context.Context, string, []string) int
type sudoAggregateReader func(context.Context) ([]byte, error)

type effectiveCheck struct {
	path string
	args []string
	want int
}

func currentPolicySubject() (string, error) {
	uid := os.Getuid()
	if uid == 0 || os.Geteuid() != uid {
		return "", errProbeBlocked
	}
	data, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return "", errProbeBlocked
	}
	end := bytes.LastIndexByte(data, ')')
	if end < 0 || end+2 >= len(data) {
		return "", errProbeBlocked
	}
	fields := strings.Fields(string(data[end+2:]))
	if len(fields) <= 19 {
		return "", errProbeBlocked
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || start == 0 {
		return "", errProbeBlocked
	}
	return fmt.Sprintf("%d,%d,%d", os.Getpid(), start, uid), nil
}

func otherAuthorityUnit(enrolled []string) string {
	for n := 0; n <= 64; n++ {
		candidate := fmt.Sprintf("vsk-authority-denied-%d.service", n)
		found := false
		for _, unit := range enrolled {
			if unit == candidate {
				found = true
				break
			}
		}
		if !found {
			return candidate
		}
	}
	return ""
}

// The service qualifies the exact sudo surface and asks one trusted, read-only
// helper to query polkit with action details.
func effectiveAuthorityPolicy(ctx context.Context, unit, subject string, enrolled []string, run policyCommandRunner, aggregate sudoAggregateReader, rootCheck func(context.Context, string, string) bool) bool {
	if ctx == nil || ctx.Err() != nil || run == nil || aggregate == nil || rootCheck == nil || !unitNamePattern.MatchString(unit) || subject == "" || !rootCheck(ctx, unit, subject) {
		return false
	}
	checks := []effectiveCheck{
		{"/usr/bin/sudo", []string{"-n", "-l", "--", defaultNativeBinary, accessProbeMode}, 0},
		{"/usr/bin/sudo", []string{"-n", "-l", "--", defaultNativeBinary, policyCheckMode}, 0},
		{"/usr/bin/sudo", []string{"-n", "-l", "--", defaultNativeBinary, accessProbeMode, "extra"}, 1},
		{"/usr/bin/sudo", []string{"-n", "-l", "--", defaultNativeBinary, policyCheckMode, "extra"}, 1},
		{"/usr/bin/sudo", []string{"-n", "-l", "--", "/usr/bin/true"}, 1},
		{"/usr/bin/sudo", []string{"-n", "-l", "--", nsenterBinary, "--version"}, 1},
		{"/usr/bin/sudo", []string{"-n", "-l", "--", "/usr/bin/systemctl", "--version"}, 1},
		{"/usr/bin/sudo", []string{"-n", "-l", "--", defaultNativeBinary, "version"}, 1},
	}
	for _, check := range checks {
		if run(ctx, check.path, check.args) != check.want {
			return false
		}
	}
	listing, err := aggregate(ctx)
	return err == nil && exactSudoAggregate(listing)
}

// Only the root one-shot mode may query polkit with unit and verb details.
func trustedPolkitPolicy(ctx context.Context, unit, subject string, enrolled []string, run policyCommandRunner) bool {
	if ctx == nil || ctx.Err() != nil || run == nil || !unitNamePattern.MatchString(unit) || subject == "" {
		return false
	}
	other := otherAuthorityUnit(enrolled)
	if other == "" {
		return false
	}
	pk := func(action string, details ...string) []string {
		args := []string{"--action-id", action, "--process", subject}
		return append(args, details...)
	}
	manage := "org.freedesktop.systemd1.manage-units"
	checks := []effectiveCheck{
		{"/usr/bin/pkcheck", pk(manage, "--detail", "verb", "restart", "--detail", "unit", unit), 0},
		{"/usr/bin/pkcheck", pk(manage, "--detail", "verb", "stop", "--detail", "unit", unit), 1},
		{"/usr/bin/pkcheck", pk(manage, "--detail", "verb", "start", "--detail", "unit", unit), 1},
		{"/usr/bin/pkcheck", pk(manage, "--detail", "verb", "restart", "--detail", "unit", other), 1},
		{"/usr/bin/pkcheck", pk(manage), 1},
		{"/usr/bin/pkcheck", pk("org.freedesktop.systemd1.manage-unit-files"), 1},
		{"/usr/bin/pkcheck", pk("org.freedesktop.systemd1.reload-daemon"), 1},
	}
	for _, check := range checks {
		if run(ctx, check.path, check.args) != check.want {
			return false
		}
	}
	return true
}

// sudo has no structured effective-policy output. Restrict its C-locale listing
// to a two exact command lines; unknown formats or extra grants fail closed.
func exactSudoAggregate(data []byte) bool {
	if len(data) == 0 || len(data) > 4096 || !bytes.HasSuffix(data, []byte("\n")) {
		return false
	}
	listing := string(data)
	const header = "\nUser vsk-labs may run the following commands on "
	before, commands, found := strings.Cut(listing, header)
	if !found || strings.Contains(before, "User vsk-labs may run") || strings.Count(commands, "\n") != 3 {
		return false
	}
	line := commands[strings.IndexByte(commands, '\n')+1:]
	return line == "    (root) NOPASSWD: "+defaultNativeBinary+" "+accessProbeMode+"\n"+"    (root) NOPASSWD: "+defaultNativeBinary+" "+policyCheckMode+"\n"
}

func readEffectiveSudoAggregate(ctx context.Context) ([]byte, error) {
	trusted, err := openTrustedExecutable("/usr/bin/sudo")
	if err != nil {
		return nil, errProbeBlocked
	}
	defer trusted.Close()
	bounded, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	cmd := exec.CommandContext(bounded, "/usr/bin/sudo", "-n", "-l")
	cmd.Env = []string{"LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin"}
	cmd.Stdin = strings.NewReader("")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if cmd.Run() != nil || bounded.Err() != nil || stderr.Len() != 0 || stdout.Len() > 4096 {
		return nil, errProbeBlocked
	}
	return stdout.Bytes(), nil
}

func runEffectivePolicyCommand(ctx context.Context, path string, args []string) int {
	trusted, err := openTrustedExecutable(path)
	if err != nil {
		return -1
	}
	defer trusted.Close()
	bounded, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	cmd := exec.CommandContext(bounded, path, args...)
	cmd.Env = []string{"LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin"}
	cmd.Stdin = strings.NewReader("")
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	err = cmd.Run()
	if bounded.Err() != nil {
		return -1
	}
	if err == nil {
		return 0
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode()
	}
	return -1
}
