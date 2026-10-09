//go:build linux

package debianbaseline

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"strconv"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"golang.org/x/sys/unix"
)

func VerifyVolumeRecovery(ctx context.Context, in generated.VolumeRecoveryInput) ([]generated.AccessMeasurement, error) {
	if os.Geteuid() != 0 {
		return nil, errVolume
	}
	return verifyVolumeRecoveryFiles(ctx, "/", 0, in, nativeVolumeRecovery, time.Now())
}
func nativeVolumeRecovery(ctx context.Context, tool []byte, header, key *os.File, slot int64) error {
	if ctx == nil || slot < 0 || slot > 31 {
		return errVolume
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	// Cryptsetup may auto-repair inconsistent LUKS2 metadata. Give it only a
	// sealed anonymous header copy: even root cannot write or resize it, and
	// the actual device/custodian header is never exposed to the child.
	headerBytes, e := readVolumeBounded(header, maximumVolumeHeader)
	if e != nil {
		return e
	}
	sealed, e := sealedVolumeHeader(headerBytes)
	if e != nil {
		return e
	}
	defer sealed.Close()
	// Validate metadata and selected slot before attempting the supplied key.
	raw, e := volumeCommand(ctx, tool, []string{"luksDump", "--dump-json-metadata", "/proc/self/fd/3"}, []*os.File{sealed}, 256<<10)
	info, statErr := header.Stat()
	if e != nil || statErr != nil {
		return errVolume
	}
	if _, e = parseVolumeMetadata(raw, slot, info.Size()); e != nil {
		return e
	}
	private, e := readVolumeKey(key)
	if e != nil {
		return e
	}
	defer clear(private)
	read, write, e := os.Pipe()
	if e != nil {
		return errVolume
	}
	defer read.Close()
	defer write.Close()
	// Linux PIPE_BUF is at least 4096; the bounded key fits before child startup.
	if n, e := write.Write(private); e != nil || n != len(private) {
		return errVolume
	}
	write.Close()
	_, e = volumeCommand(ctx, tool, []string{"open", "--test-passphrase", "--type", "luks2", "--disable-external-tokens", "--disable-keyring", "--batch-mode", "--tries", "1", "--key-slot", strconv.FormatInt(slot, 10), "--key-file", "/proc/self/fd/4", "/proc/self/fd/3"}, []*os.File{sealed, read}, 8192)
	return e
}

type volumeOutput struct {
	raw   []byte
	limit int
}

func (v *volumeOutput) Write(p []byte) (int, error) {
	if len(p) > v.limit-len(v.raw) {
		return 0, errVolume
	}
	v.raw = append(v.raw, p...)
	return len(p), nil
}
func volumeCommand(ctx context.Context, tool []byte, args []string, files []*os.File, maximum int) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	if len(tool) < 4 || !bytes.Equal(tool[:4], []byte{0x7f, 'E', 'L', 'F'}) {
		return nil, errVolume
	}
	executable, e := sealedVolumeObject(tool, 32<<20)
	if e != nil {
		return nil, e
	}
	defer executable.Close()
	// The child executes the sealed, verified ELF bytes, never a re-resolved path.
	executableFD := 3 + len(files)
	cmd := exec.CommandContext(ctx, "/proc/self/fd/"+strconv.Itoa(executableFD), args...)
	cmd.Dir = "/"
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	cmd.ExtraFiles = append(append([]*os.File(nil), files...), executable)
	cmd.Stderr = io.Discard
	cmd.WaitDelay = time.Second
	out := volumeOutput{limit: maximum}
	cmd.Stdout = &out
	if cmd.Run() != nil || ctx.Err() != nil {
		return nil, errVolume
	}
	return out.raw, nil
}

func sealedVolumeHeader(raw []byte) (*os.File, error) {
	if len(raw) < 4096 {
		return nil, errVolume
	}
	return sealedVolumeObject(raw, maximumVolumeHeader)
}
func sealedVolumeObject(raw []byte, maximum int) (*os.File, error) {
	if len(raw) < 4 || len(raw) > maximum {
		return nil, errVolume
	}
	fd, e := unix.MemfdCreate("vsk-volume-header", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if e != nil {
		return nil, errVolume
	}
	f := os.NewFile(uintptr(fd), "vsk-volume-header")
	if n, e := f.Write(raw); e != nil || n != len(raw) {
		f.Close()
		return nil, errVolume
	}
	if _, e = unix.FcntlInt(uintptr(fd), unix.F_ADD_SEALS, unix.F_SEAL_WRITE|unix.F_SEAL_GROW|unix.F_SEAL_SHRINK|unix.F_SEAL_SEAL); e != nil {
		f.Close()
		return nil, errVolume
	}
	if _, e = f.Seek(0, io.SeekStart); e != nil {
		f.Close()
		return nil, errVolume
	}
	return f, nil
}
