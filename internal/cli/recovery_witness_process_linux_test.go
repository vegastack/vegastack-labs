//go:build linux && recovery_disposable

package cli

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter/recoverydenial"
	"github.com/vegastack/vegastack-labs/internal/recovery"
)

type disposableEndpoint struct {
	mu       sync.Mutex
	admitted map[string]bool
}

func (endpoint *disposableEndpoint) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost || request.URL.Path != "/probe" || request.Header.Get("X-Synthetic-Old-Identity") != "old-token" {
		writer.WriteHeader(http.StatusUnauthorized)
		return
	}
	var input disposableProbe
	if json.NewDecoder(io.LimitReader(request.Body, 1024)).Decode(&input) != nil || input.ChallengeID != "challenge-1" || input.TargetID != "target-1" || input.FormerIdentityID != "old-identity" || input.ProbeID == "" {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	endpoint.mu.Lock()
	admitted := endpoint.admitted[input.ProbeID]
	endpoint.mu.Unlock()
	if admitted {
		writer.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(writer).Encode(disposableResponse{ChallengeID: input.ChallengeID, ProbeID: input.ProbeID, Class: "admitted"})
		return
	}
	writer.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(writer).Encode(disposableResponse{ChallengeID: input.ChallengeID, ProbeID: input.ProbeID, Class: "direct-denial"})
}

type replacementDirectVerifier struct{ adapter disposableHTTPDenialAdapter }

func (verifier replacementDirectVerifier) VerifyDirectDenial(ctx context.Context, transcript recovery.DirectDenialTranscript) error {
	requirement := transcript.Requirement
	result, err := verifier.adapter.Probe(ctx, recoverydenial.Challenge{ChallengeID: transcript.ChallengeID, Kind: requirement.Kind, SubjectID: requirement.SubjectID, TargetID: requirement.TargetID, AdapterID: requirement.AdapterID, FormerIdentityID: requirement.FormerIdentityID, ProbeID: requirement.ProbeID, Deadline: transcript.ExpiresAt})
	if err != nil || result.ResponseDigest != transcript.ResponseDigest || result.ResponseClass != transcript.ResponseClass || !result.Denied {
		return recovery.ErrWitnessUnavailable
	}
	return nil
}

type replacementKeySource struct{ path string }

func (source replacementKeySource) OpenPrivate(context.Context, string) (io.ReadCloser, error) {
	return os.Open(source.path)
}

func TestRecoveryWitnessReplacementProcessHelper(t *testing.T) {
	if os.Getenv("VSK_WITNESS_REPLACEMENT_HELPER") != "1" {
		t.Skip("disposable replacement subprocess")
	}
	if os.Geteuid() != 21002 {
		t.Fatal("replacement identity mismatch")
	}
	input, err := os.ReadFile(os.Getenv("VSK_WITNESS_RESULT_PATH"))
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Data struct {
			SignedArtifactBase64    string `json:"signedArtifactBase64"`
			ProtectedEnvelopeBase64 string `json:"protectedEnvelopeBase64"`
		} `json:"data"`
	}
	if json.Unmarshal(input, &result) != nil {
		t.Fatal("invalid public result")
	}
	artifact, err := base64.RawURLEncoding.DecodeString(result.Data.SignedArtifactBase64)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := recovery.DecodeSignedWitness(artifact)
	if err != nil {
		t.Fatal(err)
	}
	pin, err := recovery.LoadSystemWitnessManifest(signed.Payload.Binding)
	if err != nil {
		t.Fatal(err)
	}
	qualified := recovery.NewQualifiedAdapters()
	qualified.Register("disposable-http-v1", replacementDirectVerifier{adapter: disposableHTTPDenialAdapter{endpoint: os.Getenv("VSK_WITNESS_COLLECT_ENDPOINT")}})
	if err := recovery.VerifyWitnessBundle(context.Background(), pin, signed.Payload.Binding, signed, pin.Requirements, qualified, time.Now().UTC()); err != nil {
		t.Fatalf("replacement rejected exact signed direct-denial bundle: %v", err)
	}
	protected, err := base64.RawURLEncoding.DecodeString(result.Data.ProtectedEnvelopeBase64)
	if err != nil {
		t.Fatal(err)
	}
	var envelope recovery.ProtectedEnvelope
	if json.Unmarshal(protected, &envelope) != nil {
		t.Fatal("invalid protected envelope")
	}
	stream, err := recovery.NewProtectedRecipient(pin, replacementKeySource{path: os.Getenv("VSK_WITNESS_RECIPIENT_KEY")}).Open(context.Background(), envelope, signed.Payload.Binding)
	if err != nil {
		t.Fatal("replacement could not open exact protected envelope")
	}
	defer stream.Reader.Close()
	material, err := io.ReadAll(io.LimitReader(stream.Reader, 4097))
	if err != nil || string(material) != "synthetic-custodian-private-canary" || stream.ReceiptID != signed.Payload.Binding.ReceiptID {
		t.Fatal("replacement material or receipt mismatch")
	}
}

func TestRecoveryWitnessCollectBuiltProcessDisposable(t *testing.T) {
	if os.Getenv("VSK_WITNESS_COLLECT_DISPOSABLE") != "1" {
		t.Skip("run only in a disposable root Linux container")
	}
	if os.Geteuid() != 0 {
		t.Fatal("disposable identity test requires root")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Fatal("not a disposable container")
	}
	const custodianUID, replacementUID, formerUID = 21001, 21002, 21003
	if _, err := os.Stat("/etc/vsk-labs/recovery"); !os.IsNotExist(err) {
		t.Fatal("protected manifest directory already exists; refusing to overwrite")
	}
	if err := os.MkdirAll("/etc/vsk-labs/recovery", 0o755); err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll("/etc/vsk-labs/recovery")
	if err := os.Chmod("/etc/vsk-labs/recovery", 0o755); err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp(os.TempDir(), "vsk-witness-collection-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	endpoint := &disposableEndpoint{admitted: make(map[string]bool)}
	server := httptest.NewServer(endpoint)
	defer server.Close()
	adminPublic, adminPrivate, _ := ed25519.GenerateKey(rand.Reader)
	witnessPublic, witnessPrivate, _ := ed25519.GenerateKey(rand.Reader)
	formerHostKey, _ := ecdh.X25519().GenerateKey(rand.Reader)
	replacementHostKey, _ := ecdh.X25519().GenerateKey(rand.Reader)
	binding := recovery.WitnessBinding{FormerHostID: "old-host", FormerInstanceID: "old-instance", ReplacementHostID: "new-host", ReplacementInstanceID: "new-instance", DraftID: "draft-1", CiphertextFingerprint: "sha256:" + strings.Repeat("a", 64), PlanDigest: "sha256:" + strings.Repeat("b", 64), RunID: "run-1", StepID: "step-1", LeaseID: "lease-1", ChallengeID: "challenge-1", ReceiptID: "receipt-1", SourceAdmissionDigest: "sha256:" + strings.Repeat("c", 64), FenceQualificationDigest: "sha256:" + strings.Repeat("d", 64), PriorEpoch: 3, NewEpoch: 4, StateRevision: 9}
	kinds := []struct {
		kind   string
		probes []string
	}{
		{"host-service", []string{"service-denied", "alternate-process-denied"}},
		{"mesh", []string{"registration-denied", "reenrollment-denied"}},
		{"ssh", []string{"new-auth-denied", "open-session-denied"}},
		{"secret-resolver", []string{"resolve-denied", "cached-material-denied"}},
		{"provider-mutation", []string{"mutation-denied", "outstanding-session-denied"}},
		{"backup-writer", []string{"new-payload-denied", "retained-alteration-denied", "outstanding-session-denied"}},
		{"audit-writer", []string{"append-denied", "export-denied"}},
	}
	var required []recovery.BoundaryRequirement
	for _, group := range kinds {
		for _, probe := range group.probes {
			required = append(required, recovery.BoundaryRequirement{Kind: group.kind, SubjectID: "subject-1", TargetID: "target-1", AdapterID: "disposable-http-v1", FormerIdentityID: "old-identity", ProbeID: probe})
		}
	}
	now := time.Now().UTC()
	manifest := recovery.RecoveryManifest{ManifestID: "manifest-1", WitnessKeyID: "witness-key-1", WitnessInstanceID: "outside-instance", WitnessPublicKey: witnessPublic, RecipientKeyID: "recipient-1", RecipientPublicKey: replacementHostKey.PublicKey().Bytes(), Binding: binding, Requirements: required, ValidFrom: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)}
	canonical, err := recovery.CanonicalRecoveryManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestBytes, _ := json.Marshal(recovery.SignedRecoveryManifest{Payload: manifest, Signature: ed25519.Sign(adminPrivate, canonical)})
	write := func(path string, value []byte, owner int, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(path, value, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(path, owner, owner); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
	}
	write("/etc/vsk-labs/recovery/admin-root.pub", adminPublic, 0, 0o444)
	write("/etc/vsk-labs/recovery/witness-manifest.json", manifestBytes, 0, 0o444)
	keyPath := filepath.Join(dir, "witness-seed")
	materialPath := filepath.Join(dir, "custody-material")
	replacementPath := filepath.Join(dir, "replacement-host-key")
	formerPath := filepath.Join(dir, "former-host-key")
	write(keyPath, witnessPrivate.Seed(), custodianUID, 0o400)
	write(materialPath, []byte("synthetic-custodian-private-canary"), custodianUID, 0o400)
	write(replacementPath, replacementHostKey.Bytes(), replacementUID, 0o400)
	write(formerPath, formerHostKey.Bytes(), formerUID, 0o400)
	canRead := func(uid int, path string) bool {
		command := exec.Command("/usr/bin/test", "-r", path)
		command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(uid)}}
		return command.Run() == nil
	}
	if !canRead(custodianUID, keyPath) || !canRead(custodianUID, materialPath) || !canRead(replacementUID, replacementPath) || !canRead(formerUID, formerPath) || canRead(formerUID, keyPath) || canRead(replacementUID, keyPath) || canRead(custodianUID, replacementPath) || canRead(formerUID, replacementPath) || canRead(replacementUID, formerPath) {
		t.Fatal("three OS identities or two host keys are not isolated")
	}
	input, _ := json.Marshal(witnessCollectionInput{Binding: binding})
	inputPath := filepath.Join(dir, "input.json")
	write(inputPath, input, custodianUID, 0o400)
	binaryPath := filepath.Join(dir, "vsk-labs-fixture")
	build := exec.Command("go", "build", "-tags", "recovery_disposable", "-o", binaryPath, "./cmd/vsk-labs")
	build.Dir = filepath.Join("..", "..")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build disposable vsk-labs: %v: %s", err, output)
	}
	key, err := os.Open(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Close()
	material, err := os.Open(materialPath)
	if err != nil {
		t.Fatal(err)
	}
	defer material.Close()
	run := func() ([]byte, error) {
		_, _ = key.Seek(0, io.SeekStart)
		_, _ = material.Seek(0, io.SeekStart)
		command := exec.Command(binaryPath, "recovery", "witness", "collect", "--file", inputPath, "--signing-key-fd", "3", "--material-fd", "4", "--output", "json")
		command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: custodianUID, Gid: custodianUID}}
		command.ExtraFiles = []*os.File{key, material}
		command.Env = append(os.Environ(), "VSK_WITNESS_COLLECT_DISPOSABLE=1", "VSK_WITNESS_COLLECT_ENDPOINT="+server.URL)
		return command.CombinedOutput()
	}
	output, err := run()
	if err != nil || !bytes.Contains(output, []byte(`"status":"succeeded"`)) || bytes.Contains(output, []byte("synthetic-custodian-private-canary")) {
		t.Fatalf("finite custodian process failed: %v: %s", err, output)
	}
	resultPath := filepath.Join(dir, "result.json")
	write(resultPath, output, replacementUID, 0o400)
	// Go's own test binary sits below a root-only build directory. Publish an
	// executable copy solely inside this disposable fixture for the replacement.
	testBinary, err := os.Open(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	defer testBinary.Close()
	replacementBinaryPath := filepath.Join(dir, "replacement-fixture-test")
	replacementBinary, err := os.OpenFile(replacementBinaryPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(replacementBinary, testBinary); err != nil {
		t.Fatal(err)
	}
	if err := replacementBinary.Close(); err != nil {
		t.Fatal(err)
	}
	replacement := exec.Command(replacementBinaryPath, "-test.run=^TestRecoveryWitnessReplacementProcessHelper$", "-test.v=false")
	replacement.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: replacementUID, Gid: replacementUID}}
	replacement.Env = append(os.Environ(), "VSK_WITNESS_REPLACEMENT_HELPER=1", "VSK_WITNESS_RESULT_PATH="+resultPath, "VSK_WITNESS_RECIPIENT_KEY="+replacementPath, "VSK_WITNESS_COLLECT_ENDPOINT="+server.URL)
	if result, err := replacement.CombinedOutput(); err != nil {
		t.Fatalf("replacement process rejected witness: %v: %s", err, result)
	}
	for _, probe := range []string{"reenrollment-denied", "open-session-denied", "outstanding-session-denied", "retained-alteration-denied", "export-denied"} {
		endpoint.mu.Lock()
		endpoint.admitted[probe] = true
		endpoint.mu.Unlock()
		if deniedOutput, err := run(); err == nil || !bytes.Contains(deniedOutput, []byte(`"status":"blocked"`)) {
			t.Fatalf("old identity admitted at %s but collection passed: %v: %s", probe, err, deniedOutput)
		}
		endpoint.mu.Lock()
		delete(endpoint.admitted, probe)
		endpoint.mu.Unlock()
	}
	// Public JSON cannot choose applicability: the signed manifest supplies it.
	if _, err := recovery.ParseSignedRecoveryManifest(manifestBytes, adminPublic, binding, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
}
