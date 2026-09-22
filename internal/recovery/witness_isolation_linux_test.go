//go:build linux

package recovery

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestWitnessIsolationHelper(t *testing.T) {
	if os.Getenv("VSK_WITNESS_ISOLATION_HELPER") != "1" {
		t.Skip("isolated subprocess helper")
	}
	path := os.Getenv("VSK_WITNESS_ISOLATION_PATH")
	data, err := os.ReadFile(path)
	if err != nil {
		_, _ = os.Stdout.WriteString("denied")
		os.Exit(0)
	}
	if os.Getenv("VSK_WITNESS_ISOLATION_SIGN") == "1" {
		if len(data) != ed25519.PrivateKeySize {
			t.Fatal("invalid fixture key")
		}
		client := &http.Client{Timeout: 2 * time.Second}
		for _, probeID := range strings.Split(os.Getenv("VSK_WITNESS_ISOLATION_PROBES"), ",") {
			input, _ := json.Marshal(isolatedProbe{ChallengeID: "challenge-1", TargetID: "target-1", FormerIdentityID: "old-identity", ProbeID: probeID})
			request, err := http.NewRequest(http.MethodPost, os.Getenv("VSK_WITNESS_ISOLATION_PROBE_URL")+"/probe", bytes.NewReader(input))
			if err != nil {
				t.Fatal("isolated probe request invalid")
			}
			request.Header.Set("X-Synthetic-Old-Identity", "old-token")
			response, err := client.Do(request)
			if err != nil || response.StatusCode != http.StatusForbidden {
				t.Fatal("former identity still admitted by isolated endpoint")
			}
			_ = response.Body.Close()
		}
		signature := ed25519.Sign(ed25519.PrivateKey(data), []byte("synthetic-independent-recovery-challenge"))
		_, _ = os.Stdout.WriteString(hex.EncodeToString(signature))
		for i := range data {
			data[i] = 0
		}
		os.Exit(0)
	}
	_, _ = os.Stdout.WriteString("allowed")
	for i := range data {
		data[i] = 0
	}
	os.Exit(0)
}

func TestWitnessAcceptanceSeparatesLinuxProcessIdentities(t *testing.T) {
	if os.Getenv("VSK_WITNESS_ISOLATION") != "1" {
		t.Skip("disposable root Linux identity fixture")
	}
	if os.Geteuid() != 0 {
		t.Fatal("identity fixture requires disposable root")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Fatal("identity fixture may run only in disposable container")
	}
	const witnessUID = uint32(21001)
	const replacementUID = uint32(21002)
	const formerUID = uint32(21003)
	dir := t.TempDir()
	if err := os.Chmod(filepath.Dir(dir), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := httptest.NewServer(&isolatedDenialEndpoint{admitted: map[string]bool{}})
	defer endpoint.Close()
	var probeIDs []string
	for _, probes := range allowedProbes {
		for probeID := range probes {
			probeIDs = append(probeIDs, probeID)
		}
	}
	witnessKey := filepath.Join(dir, "witness-private")
	material := filepath.Join(dir, "witness-material")
	recipientKey := filepath.Join(dir, "replacement-recipient-private")
	for _, item := range []struct {
		path  string
		value []byte
		owner uint32
	}{{witnessKey, private, witnessUID}, {material, []byte("synthetic-protected-material"), witnessUID}, {recipientKey, make([]byte, 32), replacementUID}} {
		if err := os.WriteFile(item.path, item.value, 0o400); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(item.path, int(item.owner), int(item.owner)); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(item.path, 0o400); err != nil {
			t.Fatal(err)
		}
	}
	run := func(uid uint32, path string, sign bool) string {
		command := exec.Command(os.Args[0], "-test.run=^TestWitnessIsolationHelper$", "-test.v=false")
		command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: uid}}
		command.Env = append(os.Environ(), "VSK_WITNESS_ISOLATION_HELPER=1", "VSK_WITNESS_ISOLATION_PATH="+path)
		if sign {
			command.Env = append(command.Env, "VSK_WITNESS_ISOLATION_SIGN=1", "VSK_WITNESS_ISOLATION_PROBE_URL="+endpoint.URL, "VSK_WITNESS_ISOLATION_PROBES="+strings.Join(probeIDs, ","))
		}
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("isolated UID %d helper failed: %v", uid, err)
		}
		return strings.TrimSpace(string(output))
	}
	signed := run(witnessUID, witnessKey, true)
	signature, err := hex.DecodeString(signed)
	if err != nil || !ed25519.Verify(public, []byte("synthetic-independent-recovery-challenge"), signature) {
		t.Fatalf("witness process did not sign challenge: output=%q decode=%v", signed, err)
	}
	if run(witnessUID, material, false) != "allowed" || run(replacementUID, recipientKey, false) != "allowed" {
		t.Fatal("authorized holder could not read its own protected input")
	}
	for _, uid := range []uint32{replacementUID, formerUID} {
		if run(uid, witnessKey, false) != "denied" || run(uid, material, false) != "denied" {
			t.Fatal("controller identity read witness custody")
		}
	}
	for _, uid := range []uint32{witnessUID, formerUID} {
		if run(uid, recipientKey, false) != "denied" {
			t.Fatal("non-recipient identity read replacement key")
		}
	}
}
