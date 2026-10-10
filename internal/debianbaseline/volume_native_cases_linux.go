//go:build linux

package debianbaseline

import (
	"context"
	"os"
	"strconv"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"golang.org/x/sys/unix"
)

// NativeVolumeCaseObservation contains measurements only; it is never accepted
// from public reports. All altered headers and keys are sealed anonymous copies.
type NativeVolumeCaseObservation struct {
	ScenarioID, InputDigest, BindingDigest          string
	HeaderBeforeDigest, HeaderAfterDigest           string
	OriginalPolicyDigest, OriginalPolicyAfterDigest string
	TestedCopyBeforeDigest, TestedCopyAfterDigest   string
	TestedKeySlot                                   int64
	ObservedOutcome, ObservedAt                     string
}

// ObserveNativeVolumeRecoveryCase runs the owning verifier first, then a finite
// negative experiment against its exact protected custodian inputs. Originals
// stay read-only, including when cryptsetup attempts redundant-header repair.
func ObserveNativeVolumeRecoveryCase(ctx context.Context, scenario string, in generated.VolumeRecoveryInput) (NativeVolumeCaseObservation, error) {
	var out NativeVolumeCaseObservation
	if os.Geteuid() != 0 {
		return out, errVolume
	}
	switch scenario {
	case "volume-recovery-positive", "volume-wrong-key", "volume-wrong-header", "volume-wrong-slot", "volume-unchanged-after-verification", "volume-inconsistent-redundant-header":
	default:
		return out, errVolume
	}
	out.ScenarioID = scenario
	out.InputDigest = hostaction.Digest(in)
	out.BindingDigest = hostaction.Digest(in.Binding)
	policy, err := loadVolumePolicy(ctx, "/", 0, in)
	if err != nil {
		return out, err
	}
	out.OriginalPolicyDigest = hostaction.Digest(policy)
	_, err = verifyVolumeRecoveryFiles(ctx, "/", 0, in, func(ctx context.Context, tool []byte, header, key *os.File, slot int64) error {
		raw, e := readVolumeBounded(header, maximumVolumeHeader)
		if e != nil {
			return e
		}
		out.HeaderBeforeDigest = hostaction.BytesDigest(raw)
		if e = nativeVolumeRecovery(ctx, tool, header, key, slot); e != nil {
			return e
		}
		changed := append([]byte(nil), raw...)
		testedKey := key
		testedSlot := slot
		wantRefusal := false
		switch scenario {
		case "volume-wrong-key":
			private, e := readVolumeKey(key)
			if e != nil {
				return e
			}
			defer clear(private)
			private[0] ^= 0xff
			alternate, e := sealedVolumeObject(private, 4096)
			if e != nil {
				return e
			}
			defer alternate.Close()
			testedKey = alternate
			wantRefusal = true
		case "volume-wrong-header":
			secondary, e := parseVolumeHeader(raw, in.Binding.LUKSUUID)
			if e != nil || secondary+4096 > int64(len(raw)) {
				return errVolume
			}
			// Destroy both magic values on the copy; neither original is exposed.
			changed[0] ^= 0xff
			changed[secondary] ^= 0xff
			wantRefusal = true
		case "volume-wrong-slot":
			sealed, e := sealedVolumeHeader(raw)
			if e != nil {
				return e
			}
			defer sealed.Close()
			metadata, e := volumeCommand(ctx, tool, []string{"luksDump", "--dump-json-metadata", "/proc/self/fd/3"}, []*os.File{sealed}, 256<<10)
			if e != nil {
				return e
			}
			m, e := parseVolumeMetadata(metadata, slot, int64(len(raw)))
			if e != nil {
				return e
			}
			testedSlot = -1
			for candidate := int64(0); candidate < 32; candidate++ {
				if _, exists := m.Keyslots[strconv.FormatInt(candidate, 10)]; !exists {
					testedSlot = candidate
					break
				}
			}
			if testedSlot < 0 {
				return errVolume
			}
			wantRefusal = true
		case "volume-inconsistent-redundant-header":
			secondary, e := parseVolumeHeader(raw, in.Binding.LUKSUUID)
			if e != nil || secondary+4096 > int64(len(raw)) {
				return errVolume
			}
			// Corrupt the secondary binary checksum only. The intact primary remains
			// available to the real cryptsetup metadata loader and its repair path.
			changed[secondary+448] ^= 0xff
		}
		copy, e := sealedVolumeHeader(changed)
		if e != nil {
			return e
		}
		defer copy.Close()
		out.TestedCopyBeforeDigest = hostaction.BytesDigest(changed)
		out.TestedKeySlot = testedSlot
		e = nativeVolumeRecovery(ctx, tool, copy, testedKey, testedSlot)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		out.ObservedOutcome = "accepted"
		if e != nil {
			out.ObservedOutcome = "refused"
		}
		if wantRefusal && e == nil {
			return errVolume
		}
		if !wantRefusal && scenario != "volume-inconsistent-redundant-header" && e != nil {
			return e
		}
		after, e := readVolumeBounded(copy, maximumVolumeHeader)
		if e != nil {
			return e
		}
		out.TestedCopyAfterDigest = hostaction.BytesDigest(after)
		original, e := readVolumeBounded(header, maximumVolumeHeader)
		if e != nil {
			return e
		}
		out.HeaderAfterDigest = hostaction.BytesDigest(original)
		if out.TestedCopyBeforeDigest != out.TestedCopyAfterDigest || out.HeaderBeforeDigest != out.HeaderAfterDigest {
			return errVolume
		}
		return nil
	}, time.Now())
	if err != nil {
		return NativeVolumeCaseObservation{}, err
	}
	current, err := loadVolumePolicy(ctx, "/", 0, in)
	if err != nil {
		return NativeVolumeCaseObservation{}, err
	}
	out.OriginalPolicyAfterDigest = hostaction.Digest(current)
	if out.OriginalPolicyAfterDigest != out.OriginalPolicyDigest {
		return NativeVolumeCaseObservation{}, errVolume
	}
	out.ObservedAt = time.Now().UTC().Format(time.RFC3339)
	return out, nil
}

// ObserveNativeVolumeMappingCase measures the actual kernel mapping through the
// production collector, then verifies either a changed binding refusal or a
// status read using a damaged secondary header on a sealed copy.
func ObserveNativeVolumeMappingCase(ctx context.Context, scenario string, in generated.DebianBaselineInput) (NativeVolumeCaseObservation, error) {
	var out NativeVolumeCaseObservation
	if os.Geteuid() != 0 || len(in.Volumes) != 1 || len(in.ControlIDs) != 1 {
		return out, errVolume
	}
	switch scenario {
	case "volume-effective-mapping", "volume-wrong-mapping", "volume-status-no-original-repair":
	default:
		return out, errVolume
	}
	if _, err := ObserveVolumes(ctx, in); err != nil {
		return out, err
	}
	b := in.Volumes[0]
	out = NativeVolumeCaseObservation{ScenarioID: scenario, InputDigest: hostaction.Digest(in), BindingDigest: hostaction.Digest(b), TestedKeySlot: b.KeySlot, ObservedOutcome: "accepted"}
	// Resolve the exact kernel device by its pinned device number, then verify
	// the opened descriptor rather than trusting the /dev/block symlink text.
	device, err := os.Open("/dev/block/" + strconv.FormatInt(b.DeviceMajor, 10) + ":" + strconv.FormatInt(b.DeviceMinor, 10))
	if err != nil {
		return out, errVolume
	}
	defer device.Close()
	var st unix.Stat_t
	if unix.Fstat(int(device.Fd()), &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFBLK || st.Uid != 0 || int64(unix.Major(uint64(st.Rdev))) != b.DeviceMajor || int64(unix.Minor(uint64(st.Rdev))) != b.DeviceMinor {
		return out, errVolume
	}
	raw := make([]byte, b.HeaderBytes)
	if _, err = device.ReadAt(raw, 0); err != nil {
		return out, errVolume
	}
	out.HeaderBeforeDigest = hostaction.BytesDigest(raw)
	if out.HeaderBeforeDigest != b.HeaderDigest {
		return out, errVolume
	}
	out.OriginalPolicyDigest = hostaction.Digest(b)
	out.OriginalPolicyAfterDigest = out.OriginalPolicyDigest
	tested := append([]byte(nil), raw...)
	switch scenario {
	case "volume-wrong-mapping":
		wrong := b
		wrong.MappingDigest = hostaction.BytesDigest([]byte("native deliberately different mapping"))
		if wrong.MappingDigest == b.MappingDigest {
			return out, errVolume
		}
		if _, err = observeVolume(ctx, wrong); err == nil || ctx.Err() != nil {
			return out, errVolume
		}
		out.ObservedOutcome = "refused"
	case "volume-status-no-original-repair":
		offset, e := parseVolumeHeader(raw, b.LUKSUUID)
		if e != nil || offset+4096 > int64(len(raw)) {
			return out, errVolume
		}
		tested[offset+448] ^= 0xff
		copy, e := sealedVolumeHeader(tested)
		if e != nil {
			return out, e
		}
		defer copy.Close()
		f, e := openVolumeProtected("/", "usr/sbin/cryptsetup", 0, false)
		if e != nil {
			return out, e
		}
		defer f.Close()
		tool, e := readVolumeBounded(f, 32<<20)
		if e != nil {
			return out, e
		}
		_, e = volumeCommand(ctx, tool, []string{"status", "--header", "/proc/self/fd/3", b.MapperName}, []*os.File{copy}, 8192)
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		if e != nil {
			out.ObservedOutcome = "refused"
		}
		after, e := readVolumeBounded(copy, maximumVolumeHeader)
		if e != nil || hostaction.BytesDigest(after) != hostaction.BytesDigest(tested) {
			return out, errVolume
		}
	}
	out.TestedCopyBeforeDigest = hostaction.BytesDigest(tested)
	out.TestedCopyAfterDigest = out.TestedCopyBeforeDigest
	after := make([]byte, b.HeaderBytes)
	if _, err = device.ReadAt(after, 0); err != nil {
		return out, errVolume
	}
	out.HeaderAfterDigest = hostaction.BytesDigest(after)
	if out.HeaderAfterDigest != out.HeaderBeforeDigest {
		return out, errVolume
	}
	if _, err = ObserveVolumes(ctx, in); err != nil {
		return out, err
	}
	out.ObservedAt = time.Now().UTC().Format(time.RFC3339)
	return out, nil
}

// ObserveNativeVolumeRevokedBinding requires an actually installed current
// policy and a former reference to that same header/key binding. It never edits
// policy. Installing the new policy is a separately scoped fixture operation.
func ObserveNativeVolumeRevokedBinding(ctx context.Context, current, prior generated.VolumeRecoveryInput) (NativeVolumeCaseObservation, error) {
	var out NativeVolumeCaseObservation
	if os.Geteuid() != 0 || !VolumeRecoveryRotationMatches(current, prior) {
		return out, errVolume
	}
	measured, err := ObserveNativeVolumeRecoveryCase(ctx, "volume-recovery-positive", current)
	if err != nil {
		return out, err
	}
	if _, err = VerifyVolumeRecovery(ctx, prior); err == nil || ctx.Err() != nil {
		return out, errVolume
	}
	after, err := ObserveNativeVolumeRecoveryCase(ctx, "volume-recovery-positive", current)
	if err != nil || after.HeaderBeforeDigest != measured.HeaderBeforeDigest || after.OriginalPolicyDigest != measured.OriginalPolicyDigest {
		return out, errVolume
	}
	measured.ScenarioID = "volume-revoked-binding"
	measured.ObservedOutcome = "refused"
	measured.ObservedAt = after.ObservedAt
	return measured, nil
}
