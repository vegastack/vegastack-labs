//go:build linux

package server

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

func TestRecoveryReceiveInheritedBoundaryChild(t *testing.T) {
	if os.Getenv("VSK_RECEIVE_FD_TEST") != "1" {
		t.Skip("subprocess helper")
	}
	att := os.NewFile(3, "attestation")
	candidate := os.NewFile(4, "candidate")
	journal := os.NewFile(5, "journal")
	exe := os.NewFile(6, "executable")
	if validateReceiveSealed(att, 0, 256<<10) != nil {
		t.Fatal("sealed attestation rejected")
	}
	raw, err := io.ReadAll(att)
	var a recoveryReceiveAttestation
	if err != nil || json.Unmarshal(raw, &a) != nil || validateReceiveProcess(a, candidate, journal, exe) != nil {
		t.Fatal("inherited root provenance rejected")
	}
}
func TestRecoveryReceiveRootForkDropsUIDWithSealedFiles(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires approved disposable Linux root test")
	}
	executable, err := os.Open("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	defer executable.Close()
	digest, err := receiveExecutableDigest(executable)
	if err != nil {
		t.Fatal("test executable must be root-owned and not group/world writable")
	}
	ticks, err := receiveProcessStart(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	for _, variant := range []string{"valid", "unsealed", "wrong-size", "wrong-parent", "wrong-executable", "wrong-role-executable"} {
		t.Run(variant, func(t *testing.T) {
			candidate, e := newReceiveMemfd("test-candidate")
			if e != nil {
				t.Fatal(e)
			}
			defer candidate.Close()
			candidate.Write([]byte("candidate"))
			journal, e := newReceiveMemfd("test-journal")
			if e != nil {
				t.Fatal(e)
			}
			defer journal.Close()
			journal.Write([]byte("journal"))
			if variant != "unsealed" {
				if sealReceiveFile(candidate) != nil {
					t.Fatal("seal")
				}
			} else {
				candidate.Seek(0, io.SeekStart)
			}
			if sealReceiveFile(journal) != nil {
				t.Fatal("seal")
			}
			a := recoveryReceiveAttestation{ParentPID: os.Getpid(), ParentStart: ticks, ExecutableDigest: digest, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano), Bundle: generated.HostActionBundle{ExpiresAt: time.Now().Add(time.Minute).UTC().Format(time.RFC3339)}, Descriptor: generated.ControlRecoveryReceiveInput{CandidateBytes: 9, JournalBytes: 7, RoleInput: generated.LinuxRoleInput{ExecutableDigest: digest}}}
			if variant == "wrong-size" {
				a.Descriptor.CandidateBytes++
			}
			if variant == "wrong-parent" {
				a.ParentStart++
			}
			if variant == "wrong-role-executable" {
				a.Descriptor.RoleInput.ExecutableDigest = "wrong"
			}
			if variant == "wrong-executable" {
				a.ExecutableDigest = "wrong"
			}
			att, e := newReceiveMemfd("test-attestation")
			if e != nil {
				t.Fatal(e)
			}
			defer att.Close()
			raw, _ := json.Marshal(a)
			att.Write(raw)
			if sealReceiveFile(att) != nil {
				t.Fatal("seal")
			}
			command := exec.Command("/proc/self/exe", "-test.run=^TestRecoveryReceiveInheritedBoundaryChild$")
			command.Env = []string{"VSK_RECEIVE_FD_TEST=1"}
			command.Dir = "/"
			command.ExtraFiles = []*os.File{att, candidate, journal, executable}
			command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534, Groups: []uint32{}}, Pdeathsig: syscall.SIGKILL}
			output, err := command.CombinedOutput()
			if (err == nil) != (variant == "valid") {
				t.Fatalf("variant %s exit=%v output=%s", variant, err, bytes.TrimSpace(output))
			}
		})
	}
}
