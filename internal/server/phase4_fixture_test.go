package server

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

type phase4AcceptanceOutcome struct {
	SchemaVersion int    `json:"schemaVersion"`
	Check         string `json:"check"`
	Status        string `json:"status"`
}

func runPhase4AcceptanceBuiltProbe(t *testing.T, fixture *phase3ExecutableFixture) phase4AcceptanceOutcome {
	t.Helper()
	command := exec.Command("node", filepath.Join("..", "..", "web", "e2e", "real-change-server-probe.mjs"))
	command.Env = append(os.Environ(),
		"NODE_NO_WARNINGS=1",
		"VSK_PHASE3_BASE_URL="+fixture.baseURL,
		"VSK_PHASE3_CONTROLLER_URL="+fixture.controllerURL,
		"VSK_PHASE3_ASSERTION="+fixture.assertion,
		"VSK_PHASE4_PROXY_CERTIFICATE="+fixture.certificatePath,
		"VSK_PHASE4_PROXY_PRIVATE_KEY="+fixture.privateKeyPath,
	)
	stdout := &boundedProbeOutput{limit: 16 * 1024}
	stderr := &boundedProbeOutput{limit: 512}
	command.Stdout, command.Stderr = stdout, stderr
	if err := command.Run(); err != nil {
		t.Fatalf("phase 4 built-process probe failed at %s: %v", phase4ProbeStage(stderr.String()), err)
	}
	var outcome phase4AcceptanceOutcome
	if err := json.Unmarshal(stdout.Bytes(), &outcome); err != nil {
		t.Fatal("phase 4 built-process probe returned an invalid result")
	}
	return outcome
}
