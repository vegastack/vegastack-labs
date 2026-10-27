//go:build linux

package cijobguard

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestOpenCgroupRejectsOrdinaryAndSymlink(t *testing.T) {
	root := t.TempDir()
	if err := os.Symlink(root, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{root, filepath.Join(root, "link")} {
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		group, err := OpenCgroup(f)
		f.Close()
		if err == nil {
			group.Close()
			t.Fatal("ordinary filesystem accepted")
		}
	}
	if _, err := OpenCgroup(nil); err == nil {
		t.Fatal("nil directory accepted")
	}
}

// TestNativeCgroupKill is deliberately opt-in. It creates only one unique test
// subtree; the test process never enters it. All process inputs are synthetic.
func TestNativeCgroupKill(t *testing.T) {
	if os.Getenv("VSK_CIJOBGUARD_NATIVE") != "1" {
		t.Skip("native kernel fixture not requested; no kernel qualification")
	}
	if os.Geteuid() != 0 {
		t.Fatal("authorized disposable fixture requires root")
	}
	root, err := os.MkdirTemp("/sys/fs/cgroup", "vsk-cijobguard-")
	if err != nil {
		t.Fatalf("create owned subtree: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Remove(root); err != nil {
			t.Errorf("remove owned root: %v", err)
		}
	})
	makeGroup := func(name string) *os.File {
		t.Helper()
		path := filepath.Join(root, name)
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { // Cleanup is restricted to this exact fixture-owned subtree.
			_ = os.WriteFile(filepath.Join(path, "cgroup.kill"), []byte("1"), 0)
			deadline := time.Now().Add(2 * time.Second)
			for {
				err := os.Remove(path)
				if err == nil {
					return
				}
				if time.Now().After(deadline) {
					t.Errorf("remove %s: %v", name, err)
					return
				}
				time.Sleep(10 * time.Millisecond)
			}
		})
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { f.Close() })
		return f
	}
	target := makeGroup("job")
	sibling := makeGroup("sibling")
	group, err := OpenCgroup(target)
	if err != nil {
		t.Fatalf("open real domain cgroup: %v", err)
	}
	t.Cleanup(func() { group.Close() })
	start := func(directory *os.File, tree bool) *exec.Cmd {
		t.Helper()
		var cmd *exec.Cmd
		if tree {
			cmd = exec.Command(os.Args[0], "-test.run=^TestNativeCgroupWorkload$")
			cmd.Env = append(os.Environ(), "VSK_CIJOBGUARD_WORKLOAD=1")
		} else {
			cmd = exec.Command("/bin/sleep", "60")
		}
		cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(directory.Fd())}
		return cmd
	}
	neighbor := start(sibling, false)
	if err := neighbor.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = neighbor.Process.Kill(); _ = neighbor.Wait() })
	child := start(target, true)
	output, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	child.Stderr = os.Stderr
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	t.Cleanup(func() {
		if !waited {
			_ = child.Process.Kill()
			_ = child.Wait()
		}
	})
	ready := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(output)
		if scanner.Scan() {
			ready <- scanner.Text()
		} else {
			ready <- ""
		}
	}()
	var line string
	select {
	case line = <-ready:
	case <-time.After(3 * time.Second):
		t.Fatal("descendant not ready")
	}
	parts := strings.Fields(line)
	if len(parts) != 2 || parts[0] != "grandchild" {
		t.Fatalf("invalid child readiness %q", line)
	}
	grandchild, err := strconv.Atoi(parts[1])
	if err != nil || grandchild < 2 {
		t.Fatal("invalid descendant pid")
	}
	// Prove both generations actually belong to the selected kernel subtree.
	members, err := os.ReadFile(filepath.Join(root, "job", "cgroup.procs"))
	if err != nil {
		t.Fatal(err)
	}
	memberSet := map[string]bool{}
	for _, pid := range strings.Fields(string(members)) {
		memberSet[pid] = true
	}
	if !memberSet[strconv.Itoa(child.Process.Pid)] || !memberSet[strconv.Itoa(grandchild)] {
		t.Fatal("child and descendant not both in job cgroup")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := group.Kill(ctx); err != nil {
		t.Fatalf("exact kernel kill: %v", err)
	}
	if err := child.Wait(); err == nil {
		t.Fatal("killed child exited successfully")
	}
	waited = true
	events, err := os.ReadFile(filepath.Join(root, "job", "cgroup.events"))
	if err != nil || !strings.Contains(string(events), "populated 0\n") {
		t.Fatal("job subtree did not become empty")
	}
	if err := syscall.Kill(neighbor.Process.Pid, 0); err != nil {
		t.Fatal("sibling did not survive")
	}
	// Parent remains outside both target and sibling and is still executing here.
	parentMembership, err := os.ReadFile("/proc/self/cgroup")
	if err != nil || strings.Contains(string(parentMembership), filepath.Base(root)) {
		t.Fatal("supervisor entered test subtree")
	}
	_ = makeGroup("threaded-domain")
	threaded := makeGroup("threaded-domain/threaded")
	if err := os.WriteFile(filepath.Join(root, "threaded-domain", "threaded", "cgroup.type"), []byte("threaded"), 0); err != nil {
		t.Fatalf("create threaded fixture: %v", err)
	}
	if bad, err := OpenCgroup(threaded); err == nil {
		bad.Close()
		t.Fatal("threaded subtree accepted")
	}
	group.Close()
	if err := group.Kill(ctx); err == nil {
		t.Fatal("closed handle claimed kill")
	}
	t.Log("native kernel proof: exact child+grandchild subtree emptied; sibling and outside supervisor survived; threaded/closed handles rejected")
}

func TestNativeCgroupWorkload(t *testing.T) {
	if os.Getenv("VSK_CIJOBGUARD_WORKLOAD") != "1" {
		return
	}
	grandchild := exec.Command("/bin/sleep", "60")
	if err := grandchild.Start(); err != nil {
		os.Exit(42)
	}
	_, _ = fmt.Fprintf(os.Stdout, "grandchild %d\n", grandchild.Process.Pid)
	_ = grandchild.Wait()
	os.Exit(43)
}
