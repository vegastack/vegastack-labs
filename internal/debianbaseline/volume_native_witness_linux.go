//go:build linux

package debianbaseline

import (
	"context"
	"errors"
	"io"
	"os"
	"strconv"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"golang.org/x/sys/unix"
)

// NativeVolumeSealObservation contains measured state of the anonymous copy.
// It contains neither the header nor the key and is not a public proof input.
type NativeVolumeSealObservation struct {
	HeaderBeforeDigest, HeaderAfterDigest            string
	CopyBeforeDigest, CopyAfterDigest                string
	Seals, WriteErrno, ResizeErrno, ReopenWriteErrno int
	ObservedAt                                       string
}

// ObserveNativeVolumeSeal uses the production custodian policy, protected files,
// verified cryptsetup ELF and key check. Writes target only its sealed anonymous
// copy; the original header descriptor remains read-only throughout.
func ObserveNativeVolumeSeal(ctx context.Context, in generated.VolumeRecoveryInput) (NativeVolumeSealObservation, []generated.AccessMeasurement, error) {
	var observation NativeVolumeSealObservation
	if os.Geteuid() != 0 {
		return observation, nil, errVolume
	}
	measurements, err := verifyVolumeRecoveryFiles(ctx, "/", 0, in, func(ctx context.Context, tool []byte, header, key *os.File, slot int64) error {
		raw, err := readVolumeBounded(header, maximumVolumeHeader)
		if err != nil {
			return err
		}
		observation, err = observeSealedHeader(raw)
		if err != nil {
			return err
		}
		observation.HeaderBeforeDigest = hostaction.BytesDigest(raw)
		if err = nativeVolumeRecovery(ctx, tool, header, key, slot); err != nil {
			return err
		}
		after, err := readVolumeBounded(header, maximumVolumeHeader)
		if err != nil {
			return err
		}
		observation.HeaderAfterDigest = hostaction.BytesDigest(after)
		if observation.HeaderBeforeDigest != observation.HeaderAfterDigest {
			return errVolume
		}
		observation.ObservedAt = time.Now().UTC().Format(time.RFC3339)
		return nil
	}, time.Now().UTC())
	if err != nil {
		return NativeVolumeSealObservation{}, nil, err
	}
	return observation, measurements, nil
}

func observeSealedHeader(raw []byte) (NativeVolumeSealObservation, error) {
	var out NativeVolumeSealObservation
	f, err := sealedVolumeHeader(raw)
	if err != nil {
		return out, err
	}
	defer f.Close()
	out.CopyBeforeDigest = hostaction.BytesDigest(raw)
	out.Seals, err = unix.FcntlInt(f.Fd(), unix.F_GET_SEALS, 0)
	if err != nil {
		return out, err
	}
	errno := func(err error) int {
		var value unix.Errno
		if !errors.As(err, &value) {
			return 0
		}
		return int(value)
	}
	_, err = f.WriteAt([]byte{raw[0] ^ 0xff}, 0)
	out.WriteErrno = errno(err)
	out.ResizeErrno = errno(f.Truncate(0))
	other, err := os.OpenFile("/proc/self/fd/"+strconv.Itoa(int(f.Fd())), os.O_RDWR, 0)
	if err != nil {
		return out, err
	}
	_, err = other.WriteAt([]byte{raw[0] ^ 0xff}, 0)
	out.ReopenWriteErrno = errno(err)
	if err = other.Close(); err != nil {
		return out, err
	}
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		return out, err
	}
	after, err := io.ReadAll(io.LimitReader(f, maximumVolumeHeader+1))
	if err != nil {
		return out, err
	}
	out.CopyAfterDigest = hostaction.BytesDigest(after)
	required := unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL
	if out.Seals&required != required || out.WriteErrno != int(unix.EPERM) || out.ResizeErrno != int(unix.EPERM) || out.ReopenWriteErrno != int(unix.EPERM) || out.CopyBeforeDigest != out.CopyAfterDigest {
		return out, errVolume
	}
	return out, nil
}
