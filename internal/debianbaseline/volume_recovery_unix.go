//go:build linux || darwin

package debianbaseline

import (
	"context"
	"io"
	"os"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
)

type volumeRecoveryRunner func(context.Context, *os.File, *os.File, int64) error

// Private test seam; public Linux entry points always use / and root ownership.
func verifyVolumeRecoveryFiles(ctx context.Context, root string, uid uint32, in generated.VolumeRecoveryInput, run volumeRecoveryRunner, at time.Time) ([]generated.AccessMeasurement, error) {
	if ctx == nil || ctx.Err() != nil || run == nil || ValidateVolumeBinding(in.Binding) != nil || in.HostID != in.Binding.RecoveryCustodianID || in.HostIdentityDigest != in.Binding.RecoveryCustodianIdentityDigest {
		return nil, errVolume
	}
	policy, e := loadVolumePolicy(ctx, root, uid, in)
	if e != nil {
		return nil, e
	}
	tool, e := openVolumeProtected(root, "usr/sbin/cryptsetup", uid, false)
	if e != nil {
		return nil, e
	}
	defer tool.Close()
	info, e := tool.Stat()
	if e != nil || info.Mode().Perm()&0111 == 0 || info.Size() > 32<<20 {
		return nil, errVolume
	}
	toolBytes, e := readVolumeBounded(tool, 32<<20)
	if e != nil || hostaction.BytesDigest(toolBytes) != policy.CryptsetupDigest {
		return nil, errVolume
	}
	dir := "etc/vsk-labs/volume-recovery/" + in.RecoveryReferenceID + "/"
	header, e := openVolumeProtected(root, dir+"header", uid, true)
	if e != nil {
		return nil, e
	}
	defer header.Close()
	before, e := header.Stat()
	if e != nil || before.Size() != in.Binding.HeaderBytes {
		return nil, errVolume
	}
	raw, e := readVolumeBounded(header, maximumVolumeHeader)
	if e != nil || hostaction.BytesDigest(raw) != in.Binding.HeaderDigest {
		return nil, errVolume
	}
	if _, e = parseVolumeHeader(raw, in.Binding.LUKSUUID); e != nil {
		return nil, e
	}
	key, e := openVolumeProtected(root, dir+"key", uid, true)
	if e != nil {
		return nil, e
	}
	defer key.Close()
	keyBefore, e := key.Stat()
	if e != nil || keyBefore.Size() < 8 || keyBefore.Size() > 4096 {
		return nil, errVolume
	}
	// Neither key bytes nor raw tool output are copied into measurements or errors.
	if e = run(ctx, header, key, in.Binding.KeySlot); e != nil || ctx.Err() != nil {
		return nil, errVolume
	}
	after, e := header.Stat()
	if e != nil || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return nil, errVolume
	}
	current, e := readVolumeBounded(header, maximumVolumeHeader)
	if e != nil || hostaction.BytesDigest(current) != in.Binding.HeaderDigest {
		return nil, errVolume
	}
	fresh, e := openVolumeProtected(root, dir+"header", uid, true)
	if e != nil {
		return nil, e
	}
	freshInfo, e := fresh.Stat()
	fresh.Close()
	if e != nil || !os.SameFile(before, freshInfo) {
		return nil, errVolume
	}
	keyAfter, e := key.Stat()
	if e != nil || !os.SameFile(keyBefore, keyAfter) || keyBefore.Size() != keyAfter.Size() || !keyBefore.ModTime().Equal(keyAfter.ModTime()) {
		return nil, errVolume
	}
	freshKey, e := openVolumeProtected(root, dir+"key", uid, true)
	if e != nil {
		return nil, e
	}
	freshKeyInfo, e := freshKey.Stat()
	freshKey.Close()
	if e != nil || !os.SameFile(keyBefore, freshKeyInfo) {
		return nil, errVolume
	}
	p2, e := loadVolumePolicy(ctx, root, uid, in)
	if e != nil || p2 != policy {
		return nil, errVolume
	}
	facts := hostaction.Digest(struct{ Binding, Policy, Prior string }{hostaction.Digest(in.Binding), hostaction.Digest(policy), in.PriorVolumeReceiptDigest})
	return []generated.AccessMeasurement{volumeMeasurement(in.Binding, in.ProfileLockDigest, "recovery", facts, in.PriorVolumeReceiptDigest, at)}, nil
}
func volumeMeasurement(b generated.HostVolumeBinding, lock, kind, facts, prior string, at time.Time) generated.AccessMeasurement {
	control := "linux.volume-encryption:" + b.VolumeID
	if kind == "recovery" {
		control = "linux.volume-recovery:" + b.VolumeID
	}
	v := generated.VolumeObservation{Schema: generated.SchemaIDVolumeObservation, SchemaVersion: "1.0.0", Binding: b, Kind: kind, FactsDigest: facts, PriorVolumeReceiptDigest: prior, ObservedAt: at.UTC().Format(time.RFC3339)}
	return generated.AccessMeasurement{Schema: generated.SchemaIDAccessMeasurement, SchemaVersion: "1.0.0", ControlID: control, Kind: "volume", Status: "passed", SubjectHostID: b.HostID, SubjectIdentityDigest: b.HostIdentityDigest, ProfileLockDigest: lock, ProducerID: "debian-baseline", ProducerVersion: "1.0.0", ObservedAt: v.ObservedAt, ConfigurationDigest: hostaction.Digest(b), PositiveProbeDigest: facts, NegativeProbeDigest: hostaction.BytesDigest(nil), Reason: "observed-native-volume", Volume: &v}
}
func readVolumeKey(f *os.File) ([]byte, error) {
	if _, e := f.Seek(0, io.SeekStart); e != nil {
		return nil, errVolume
	}
	raw, e := io.ReadAll(io.LimitReader(f, 4097))
	if e != nil || len(raw) < 8 || len(raw) > 4096 {
		clear(raw)
		return nil, errVolume
	}
	return raw, nil
}
