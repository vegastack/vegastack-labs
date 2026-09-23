//go:build linux

package nativecredential

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type policyCheckRequest struct {
	UnitName string `json:"unit_name"`
	Subject  string `json:"subject"`
}

func decodePolicyCheckRequest(input io.Reader) (policyCheckRequest, error) {
	data, err := io.ReadAll(io.LimitReader(input, 513))
	if err != nil || len(data) > 512 {
		return policyCheckRequest{}, errProbeBlocked
	}
	var request policyCheckRequest
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || decoder.Decode(new(any)) != io.EOF || !unitNamePattern.MatchString(request.UnitName) {
		return policyCheckRequest{}, errProbeBlocked
	}
	return request, nil
}

func exactLivePolicySubject(subject string, sudoUID string) bool {
	parts := strings.Split(subject, ",")
	if len(parts) != 3 || parts[2] != sudoUID {
		return false
	}
	pid, err := strconv.Atoi(parts[0])
	if err != nil || pid <= 1 {
		return false
	}
	start, err := strconv.ParseUint(parts[1], 10, 64)
	if err != nil || start == 0 {
		return false
	}
	uid, err := strconv.ParseUint(parts[2], 10, 32)
	if err != nil || uid == 0 {
		return false
	}
	stat, err := os.ReadFile("/proc/" + parts[0] + "/stat")
	if err != nil {
		return false
	}
	end := bytes.LastIndexByte(stat, ')')
	if end < 0 || end+2 >= len(stat) {
		return false
	}
	fields := strings.Fields(string(stat[end+2:]))
	if len(fields) <= 19 || fields[19] != parts[1] {
		return false
	}
	status, err := os.ReadFile("/proc/" + parts[0] + "/status")
	if err != nil {
		return false
	}
	found := false
	for _, line := range strings.Split(string(status), "\n") {
		if strings.HasPrefix(line, "Uid:") {
			ids := strings.Fields(strings.TrimPrefix(line, "Uid:"))
			if len(ids) != 4 {
				return false
			}
			for _, id := range ids {
				if id != parts[2] {
					return false
				}
			}
			found = true
		}
	}
	return found
}

// RunPolicyCheckMode is an exact-argv sudoers entry. It only asks polkit for
// read-only decisions; no systemd operation or secret access occurs here.
func RunPolicyCheckMode(ctx context.Context, input io.Reader) int {
	if ctx == nil || ctx.Err() != nil || os.Getuid() != 0 || os.Geteuid() != 0 || os.Getenv("SUDO_USER") != "vsk-labs" {
		return 2
	}
	sudoUID := os.Getenv("SUDO_UID")
	request, err := decodePolicyCheckRequest(input)
	if err != nil || !exactLivePolicySubject(request.Subject, sudoUID) {
		return 2
	}
	policy, err := readProbePolicy(probePolicyPath)
	if err != nil {
		return 2
	}
	machine, err := os.ReadFile("/etc/machine-id")
	if err != nil || strings.TrimSpace(string(machine)) != policy.MachineID {
		return 2
	}
	enrolled := false
	for _, unit := range policy.Units {
		if unit == request.UnitName {
			enrolled = true
			break
		}
	}
	if !enrolled || !systemdUnitRootSafe(request.UnitName) {
		return 2
	}
	if !trustedPolkitPolicy(ctx, request.UnitName, request.Subject, policy.Units, runEffectivePolicyCommand) {
		return 2
	}
	if !exactLivePolicySubject(request.Subject, sudoUID) {
		return 2
	}
	return 0
}

func requestRootPolicyCheck(ctx context.Context, unit, subject string) bool {
	if ctx == nil || ctx.Err() != nil {
		return false
	}
	data, err := json.Marshal(policyCheckRequest{UnitName: unit, Subject: subject})
	if err != nil || len(data) > 512 {
		return false
	}
	trusted, err := openTrustedExecutable("/usr/bin/sudo")
	if err != nil {
		return false
	}
	defer trusted.Close()
	bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(bounded, "/usr/bin/sudo", "-n", "--", defaultNativeBinary, policyCheckMode)
	cmd.Env = []string{"LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin"}
	cmd.Stdin = bytes.NewReader(data)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	return cmd.Run() == nil && bounded.Err() == nil && stdout.Len() == 0 && stderr.Len() == 0
}
