//go:build linux

package cijobrunner

import (
	"bufio"
	"context"
	"encoding/json"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
)

type nativeDispatcher struct{ executable string }

func NewNativeDispatcher(executable string) hostaction.Dispatcher {
	return nativeDispatcher{executable}
}
func (d nativeDispatcher) Lookup(id, version string) (hostaction.Handler, bool) {
	if id != hostaction.CIJobAction || version != "1.0.0" || os.Geteuid() != 0 {
		return nil, false
	}
	c, e := LoadNativeConfig(ConfigPath)
	if e != nil {
		return nil, false
	}
	return &nativeBridge{config: c, executable: d.executable}, true
}

type nativeBridge struct {
	config     NativeConfig
	executable string
}

func (h *nativeBridge) Execute(context.Context, generated.HostActionBundle) (generated.HostActionResult, error) {
	return generated.HostActionResult{}, ErrBlocked
}
func (h *nativeBridge) Verify(_ context.Context, b generated.HostActionBundle, r generated.HostActionResult) error {
	d, e := hostaction.BundleDigest(b)
	if e != nil || d != r.BundleDigest || hostaction.ValidateResult(r) != nil {
		return ErrBlocked
	}
	return nil
}
func (h *nativeBridge) ExecuteCI(ctx context.Context, b generated.HostActionBundle, input io.ReadCloser, output io.Writer) (generated.HostActionResult, error) {
	var result generated.HostActionResult
	if _, _, e := h.config.Load(ctx, b); e != nil {
		return result, e
	}
	if hash, e := fileDigest(h.executable); e != nil || hash != h.config.Profile.ExecutableDigest {
		return result, ErrBlocked
	}
	var networkParent, networkChild *os.File
	if !h.config.Profile.Offline {
		pair, e := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if e != nil {
			return result, ErrBlocked
		}
		networkParent = os.NewFile(uintptr(pair[0]), "root network verifier")
		networkChild = os.NewFile(uintptr(pair[1]), "private network verifier")
		defer networkParent.Close()
		defer networkChild.Close()
	}
	cmd := exec.Command(h.executable, WorkerMode)
	if networkChild != nil {
		cmd.ExtraFiles = []*os.File{networkChild}
	}
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: h.config.Profile.DaemonUID, Gid: h.config.DaemonGID, Groups: []uint32{}}, Pdeathsig: syscall.SIGTERM}
	cmd.Stderr = io.Discard
	in, e := cmd.StdinPipe()
	if e != nil {
		return result, ErrBlocked
	}
	out, writer, e := os.Pipe()
	if e != nil {
		return result, ErrBlocked
	}
	cmd.Stdout = writer
	if cmd.Start() != nil {
		in.Close()
		out.Close()
		writer.Close()
		return result, ErrBlocked
	}
	writer.Close()
	if networkChild != nil {
		networkChild.Close()
		go serveNetwork(ctx, networkParent, h.config)
	}
	defer out.Close()
	// TERM preserves the finite worker's cleanup defer. Its independent signed
	// deadline remains authoritative; parent never kills only its held hook.
	stop := context.AfterFunc(ctx, func() { _ = cmd.Process.Signal(syscall.SIGTERM); input.Close() })
	defer stop()
	if hostaction.WriteFrame(in, nativeBootstrap{Config: h.config, Bundle: b}, hostaction.MaximumEnvelope) != nil {
		in.Close()
		_ = cmd.Process.Signal(syscall.SIGTERM)
		_ = cmd.Wait()
		return result, ErrBlocked
	}
	copied := make(chan struct{})
	go func() { _, _ = io.Copy(in, input); in.Close(); close(copied) }()
	defer func() { input.Close(); in.Close(); <-copied }()
	reader := bufio.NewReaderSize(out, hostaction.MaximumResultFrame+2)
	for {
		raw, e := hostaction.ReadFrame(reader, hostaction.MaximumResultFrame)
		if e != nil {
			_ = cmd.Process.Signal(syscall.SIGTERM)
			_ = cmd.Wait()
			return result, ErrBlocked
		}
		var tag struct{ Kind, Schema string }
		if json.Unmarshal(raw, &tag) != nil {
			return result, ErrProtocol
		}
		if tag.Schema == generated.SchemaIDHostActionResult {
			if generated.ValidateContractJSON(tag.Schema, raw, generated.ContractExact) != nil || json.Unmarshal(raw, &result) != nil || cmd.Wait() != nil {
				return result, ErrBlocked
			}
			return result, nil
		}
		var f frame
		if decodeFrame(ctx, raw, &f) != nil || f.Kind == "registration" || f.Kind == "start" || f.Kind == "decision" {
			_ = cmd.Process.Signal(syscall.SIGTERM)
			_ = cmd.Wait()
			return result, ErrProtocol
		}
		if len(raw) > maxFrame {
			return result, ErrProtocol
		}
		if _, e = output.Write(append(raw, '\n')); e != nil {
			_ = cmd.Process.Signal(syscall.SIGTERM)
			_ = cmd.Wait()
			return result, ErrBlocked
		}
	}
}

// RunWorker is a finite, demoted child of the root signed-action helper. It has
// no public command flags, provider secret resolver, or standalone authority.
func RunWorker(ctx context.Context, input io.ReadCloser, output io.Writer) error {
	parent, e := os.ReadFile("/proc/" + strconv.Itoa(os.Getppid()) + "/status")
	if e != nil {
		return ErrBlocked
	}
	rootParent := false
	for _, line := range strings.Split(string(parent), "\n") {
		f := strings.Fields(line)
		if len(f) == 5 && f[0] == "Uid:" && f[1] == "0" && f[2] == "0" {
			rootParent = true
		}
	}
	if !rootParent {
		return ErrBlocked
	}
	ctx, cancel := context.WithTimeout(ctx, time.Hour)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { input.Close() })
	defer stop()
	reader := bufio.NewReaderSize(input, hostaction.MaximumEnvelope+2)
	raw, e := hostaction.ReadFrame(reader, hostaction.MaximumEnvelope)
	if e != nil {
		return ErrProtocol
	}
	var bootstrap nativeBootstrap
	if decodeFrame(ctx, raw, &bootstrap) != nil {
		return ErrProtocol
	}
	c := bootstrap.Config
	b := bootstrap.Bundle
	if uint32(os.Geteuid()) != c.Profile.DaemonUID || c.RuntimeDigest != ComputeRuntimeDigest(c.Profile) {
		return ErrBlocked
	}
	var verifier NetworkVerifier
	if !c.Profile.Offline {
		unix.CloseOnExec(3)
		f := os.NewFile(3, "private root network verifier")
		if f == nil {
			return ErrBlocked
		}
		defer f.Close()
		verifier = &networkClient{file: f, reader: bufio.NewReader(f)}
	}
	d, e := NewDocker(c.Docker, c.Profile, verifier)
	if e != nil {
		return e
	}
	handler, e := NewCIHandler(c, d)
	if e != nil {
		return e
	}
	r, e := handler.ExecuteCI(ctx, b, &workerReader{Reader: reader, Closer: input}, output)
	if e != nil {
		return e
	}
	return hostaction.WriteFrame(output, r, hostaction.MaximumResultFrame)
}

type workerReader struct {
	io.Reader
	io.Closer
}

type nativeBootstrap struct {
	Config NativeConfig               `json:"config"`
	Bundle generated.HostActionBundle `json:"bundle"`
}
