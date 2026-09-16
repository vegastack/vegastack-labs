//go:build linux

package api

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const credentialProcessCanary = "synthetic-process-private-canary"

func TestCredentialImportChildProcessKeepsPrivateBytesOffArgsEnvironmentAndTempPaths(t *testing.T) {
	if os.Getenv("VSK_CREDENTIAL_IMPORT_PROCESS_HELPER") == "1" {
		for _, value := range append(append([]string{}, os.Args...), os.Environ()...) {
			if strings.Contains(value, credentialProcessCanary) {
				os.Exit(91)
			}
		}
		private, err := io.ReadAll(io.LimitReader(os.Stdin, 4097))
		if err != nil || string(private) != credentialProcessCanary {
			os.Exit(92)
		}
		for index := range private {
			private[index] = 0
		}
		entries, err := os.ReadDir(os.TempDir())
		if err != nil || len(entries) != 0 {
			os.Exit(93)
		}
		_, _ = os.Stdout.WriteString("credential draft accepted\n")
		os.Exit(0)
	}

	temporary := t.TempDir()
	command := exec.Command(os.Args[0], "-test.run=^TestCredentialImportChildProcessKeepsPrivateBytesOffArgsEnvironmentAndTempPaths$", "--", "credential", "import", "--reference-id", "ref-a")
	command.Stdin = strings.NewReader(credentialProcessCanary)
	command.Env = []string{"VSK_CREDENTIAL_IMPORT_PROCESS_HELPER=1", "TMPDIR=" + temporary, "PATH=/usr/bin:/bin"}
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	if strings.Contains(strings.Join(command.Args, "\x00")+strings.Join(command.Env, "\x00"), credentialProcessCanary) {
		t.Fatal("private input entered argv or environment before process start")
	}
	if err := command.Run(); err != nil {
		t.Fatalf("child failed: %v stderr=%q", err, stderr.String())
	}
	if stdout.String() != "credential draft accepted\n" || stderr.Len() != 0 || strings.Contains(stdout.String()+stderr.String(), credentialProcessCanary) {
		t.Fatalf("unsafe child output stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	entries, err := os.ReadDir(temporary)
	if err != nil || len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, entry := range entries {
			names = append(names, filepath.Base(entry.Name()))
		}
		t.Fatalf("private process left temp paths: %v, %v", names, err)
	}
}
