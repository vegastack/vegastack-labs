//go:build linux

package recovery

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter/recoverydenial"
)

type sourceProcessOutput struct {
	Witness  SignedWitness     `json:"witness"`
	Envelope ProtectedEnvelope `json:"envelope"`
}

type sourceProcessRecipientKey struct{ path string }

func (source sourceProcessRecipientKey) OpenPrivate(context.Context, string) (io.ReadCloser, error) {
	return os.Open(source.path)
}

func TestSourceQualificationProcessHelper(t *testing.T) {
	role := os.Getenv("VSK_SOURCE_ADMISSION_HELPER")
	if role == "" {
		t.Skip("disposable source process helper")
	}
	directory := os.Getenv("VSK_SOURCE_ADMISSION_DIR")
	fail := func() { _, _ = os.Stdout.WriteString("denied"); os.Exit(0) }
	if role == "former" {
		for _, name := range []string{"witness.key", "witness.material", "recipient.key"} {
			if file, err := os.Open(filepath.Join(directory, name)); err == nil {
				_ = file.Close()
				fail()
			}
		}
		_, _ = os.Stdout.WriteString("denied")
		os.Exit(0)
	}
	bindingRaw, err := os.ReadFile(filepath.Join(directory, "binding.json"))
	if err != nil {
		fail()
	}
	var binding WitnessBinding
	if json.Unmarshal(bindingRaw, &binding) != nil {
		fail()
	}
	adminRoot, err := readProtectedWitnessFile(filepath.Join(directory, "admin-root.pub"), 0, ed25519.PublicKeySize)
	if err != nil {
		fail()
	}
	manifest, err := readProtectedWitnessFile(filepath.Join(directory, "witness-manifest.json"), 0, 16384)
	if err != nil {
		fail()
	}
	now := time.Now().UTC()
	pin, err := ParseSignedRecoveryManifest(manifest, adminRoot, binding, now)
	if err != nil {
		fail()
	}
	verifier := isolatedDirectVerifier{url: os.Getenv("VSK_SOURCE_ADMISSION_URL"), client: &http.Client{Timeout: 2 * time.Second}, now: now}
	if role == "custodian" {
		key, keyErr := os.Open(filepath.Join(directory, "witness.key"))
		material, materialErr := os.Open(filepath.Join(directory, "witness.material"))
		if keyErr != nil || materialErr != nil {
			if key != nil {
				_ = key.Close()
			}
			if material != nil {
				_ = material.Close()
			}
			fail()
		}
		signed, envelope, collectErr := CollectWitness(context.Background(), CollectRequest{Pin: pin, Binding: binding, Required: pin.Requirements, Adapters: map[string]recoverydenial.Adapter{"isolated-http-v1": isolatedCollectorAdapter{verifier: verifier}}, SigningKey: key, Material: material, Now: time.Now})
		if collectErr != nil {
			fail()
		}
		if json.NewEncoder(os.Stdout).Encode(sourceProcessOutput{Witness: signed, Envelope: envelope}) != nil {
			fail()
		}
		os.Exit(0)
	}
	if role != "replacement" {
		fail()
	}
	files, err := readProtectedPackageFiles(directory, 0, nil)
	if err != nil {
		fail()
	}
	signed, err := DecodeSignedWitness(files[0])
	if err != nil {
		fail()
	}
	envelope, err := decodeProtectedEnvelope(files[1], pin, binding)
	if err != nil {
		fail()
	}
	qualificationRaw, err := readProtectedWitnessFile(filepath.Join(directory, "adapter-qualifications.json"), 0, maxQualificationArtifactBytes)
	if err != nil {
		fail()
	}
	// This fixture factory exists only in a _test.go file. The production map
	// remains empty and cannot admit this disposable HTTP endpoint.
	factories := map[string]qualifiedFactory{"isolated-http-v1": {implementationDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", new: func(AdapterQualification) DirectDenialVerifier { return verifier }}}
	qualified, err := parseQualifiedAdapters(qualificationRaw, adminRoot, pin.Requirements, now, factories)
	if err != nil {
		fail()
	}
	handoff, err := VerifyInstalledSource(context.Background(), binding, pin.Requirements, InstalledPackage{Pin: pin, Witness: signed, Envelope: envelope}, qualified, now)
	if err != nil {
		fail()
	}
	recipient := NewProtectedRecipient(pin, sourceProcessRecipientKey{path: filepath.Join(directory, "recipient.key")})
	receipts := fileReceiptStore{directory: filepath.Join(directory, "receipts"), expectedUID: uint32(os.Geteuid())}
	err = handoff.ConsumeCustody(context.Background(), recipient, receipts, func(reader io.ReadCloser) error {
		material, readErr := io.ReadAll(io.LimitReader(reader, 4097))
		if readErr != nil || !bytes.Equal(material, []byte("synthetic-custodian-private-canary")) {
			return ErrWitnessUnavailable
		}
		return nil
	})
	if err != nil {
		fail()
	}
	_, _ = os.Stdout.WriteString("qualified")
	os.Exit(0)
}

func TestSourceQualificationRequiresEveryDirectBoundaryAndExternalRoot(t *testing.T) {
	if os.Getenv("VSK_SOURCE_ADMISSION") != "1" {
		t.Skip("disposable root Linux source acceptance")
	}
	if os.Geteuid() != 0 {
		t.Fatal("source acceptance requires disposable root")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Fatal("source acceptance may run only in disposable container")
	}
	const custodianUID, replacementUID, formerUID = uint32(22001), uint32(22002), uint32(22003)
	directory := t.TempDir()
	if err := os.Chmod(filepath.Dir(directory), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	endpoint := &isolatedDenialEndpoint{admitted: map[string]bool{}}
	server := httptest.NewServer(endpoint)
	defer server.Close()
	adminPublic, adminPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	witnessPublic, witnessPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, binding, _, _ := witnessFixture(t)
	now := time.Now().UTC()
	required, _, _, _ := boundaryFixture()
	required = append([]BoundaryRequirement(nil), required...)
	for i := range required {
		required[i].AdapterID = "isolated-http-v1"
	}
	payload := RecoveryManifest{ManifestID: "source-manifest-1", WitnessKeyID: "witness-key-1", WitnessInstanceID: "outside-instance", WitnessPublicKey: witnessPublic, RecipientKeyID: "recipient-1", RecipientPublicKey: recipient.PublicKey().Bytes(), Binding: binding, Requirements: required, ValidFrom: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)}
	manifestCanonical, err := CanonicalRecoveryManifest(payload)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := json.Marshal(SignedRecoveryManifest{Payload: payload, Signature: ed25519.Sign(adminPrivate, manifestCanonical)})
	if err != nil {
		t.Fatal(err)
	}
	qualificationsByGroup := make(map[string]AdapterQualification)
	for _, item := range required {
		entry := AdapterQualification{AdapterID: item.AdapterID, Kind: item.Kind, SubjectID: item.SubjectID, TargetID: item.TargetID, FormerIdentityID: item.FormerIdentityID, ImplementationDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ValidFrom: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)}
		qualificationsByGroup[qualificationKey(entry)] = entry
	}
	qualifications := make([]AdapterQualification, 0, len(qualificationsByGroup))
	for _, entry := range qualificationsByGroup {
		qualifications = append(qualifications, entry)
	}
	sort.Slice(qualifications, func(i, j int) bool { return qualificationKey(qualifications[i]) < qualificationKey(qualifications[j]) })
	qualificationPayload := QualificationRecord{RecordID: "source-qualification-1", Entries: qualifications}
	qualificationCanonical, err := CanonicalQualificationRecord(qualificationPayload)
	if err != nil {
		t.Fatal(err)
	}
	qualificationRaw, err := json.Marshal(SignedQualificationRecord{Payload: qualificationPayload, Signature: ed25519.Sign(adminPrivate, qualificationCanonical)})
	if err != nil {
		t.Fatal(err)
	}
	bindingRaw, err := json.Marshal(binding)
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string][]byte{"admin-root.pub": adminPublic, "witness-manifest.json": manifest, "adapter-qualifications.json": qualificationRaw, "binding.json": bindingRaw} {
		if err := os.WriteFile(filepath.Join(directory, name), value, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, item := range []struct {
		name  string
		value []byte
		uid   uint32
	}{{"witness.key", witnessPrivate.Seed(), custodianUID}, {"witness.material", []byte("synthetic-custodian-private-canary"), custodianUID}, {"recipient.key", recipient.Bytes(), replacementUID}} {
		path := filepath.Join(directory, item.name)
		if err := os.WriteFile(path, item.value, 0o400); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(path, int(item.uid), int(item.uid)); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o400); err != nil {
			t.Fatal(err)
		}
	}
	receiptDirectory := filepath.Join(directory, "receipts")
	if err := os.Mkdir(receiptDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(receiptDirectory, int(replacementUID), int(replacementUID)); err != nil {
		t.Fatal(err)
	}
	testExecutable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	testExecutableBytes, err := os.ReadFile(testExecutable)
	if err != nil {
		t.Fatal(err)
	}
	helperExecutable := filepath.Join(directory, "source-admission-helper")
	if err := os.WriteFile(helperExecutable, testExecutableBytes, 0o755); err != nil {
		t.Fatal(err)
	}
	run := func(uid uint32, role string) string {
		command := exec.Command(helperExecutable, "-test.run=^TestSourceQualificationProcessHelper$", "-test.v=false")
		command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: uid}}
		command.Env = append(os.Environ(), "VSK_SOURCE_ADMISSION_HELPER="+role, "VSK_SOURCE_ADMISSION_DIR="+directory, "VSK_SOURCE_ADMISSION_URL="+server.URL)
		output, commandErr := command.CombinedOutput()
		if commandErr != nil {
			t.Fatalf("%s process failed: %v", role, commandErr)
		}
		return strings.TrimSpace(string(output))
	}
	if run(formerUID, "former") != "denied" {
		t.Fatal("former identity read protected custody")
	}
	var collected sourceProcessOutput
	if json.Unmarshal([]byte(run(custodianUID, "custodian")), &collected) != nil {
		t.Fatal("custodian did not return a finite public package")
	}
	witnessRaw, err := EncodeSignedWitness(collected.Witness)
	if err != nil {
		t.Fatal(err)
	}
	envelopeRaw, err := json.Marshal(collected.Envelope)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(witnessRaw, []byte("synthetic-custodian-private-canary")) || bytes.Contains(envelopeRaw, []byte("synthetic-custodian-private-canary")) {
		t.Fatal("private material entered public package")
	}
	for name, value := range map[string][]byte{systemSignedWitnessName: witnessRaw, systemEnvelopeName: envelopeRaw} {
		if err := os.WriteFile(filepath.Join(directory, name), value, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	wrongRoot, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "admin-root.pub"), wrongRoot, 0o644); err != nil {
		t.Fatal(err)
	}
	if run(replacementUID, "replacement") != "denied" {
		t.Fatal("wrong admin root admitted")
	}
	if err := os.WriteFile(filepath.Join(directory, "admin-root.pub"), adminPublic, 0o644); err != nil {
		t.Fatal(err)
	}
	partial := collected.Witness
	partial.Payload.Transcripts = append([]DirectDenialTranscript(nil), partial.Payload.Transcripts[:1]...)
	partialCanonical, err := CanonicalWitnessPayload(partial.Payload)
	if err != nil {
		t.Fatal(err)
	}
	partial.Signature = ed25519.Sign(witnessPrivate, partialCanonical)
	partialRaw, err := EncodeSignedWitness(partial)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, systemSignedWitnessName), partialRaw, 0o644); err != nil {
		t.Fatal(err)
	}
	if run(replacementUID, "replacement") != "denied" {
		t.Fatal("missing direct probe admitted")
	}
	if err := os.WriteFile(filepath.Join(directory, systemSignedWitnessName), witnessRaw, 0o644); err != nil {
		t.Fatal(err)
	}
	endpoint.mu.Lock()
	endpoint.admitted["alternate-process-denied"] = true
	endpoint.mu.Unlock()
	if run(replacementUID, "replacement") != "denied" {
		t.Fatal("surviving former process admitted")
	}
	endpoint.mu.Lock()
	delete(endpoint.admitted, "alternate-process-denied")
	endpoint.mu.Unlock()
	if run(replacementUID, "replacement") != "qualified" {
		t.Fatal("verified source rejected")
	}
	if run(replacementUID, "replacement") != "denied" {
		t.Fatal("one-use receipt replay admitted")
	}
}
