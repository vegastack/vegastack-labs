//go:build linux

package debianbaseline

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"golang.org/x/sys/unix"
)

func ObserveVolumes(ctx context.Context, in generated.DebianBaselineInput) ([]generated.AccessMeasurement, error) {
	if os.Geteuid() != 0 || ctx == nil || ctx.Err() != nil || len(in.ControlIDs) < 1 || len(in.ControlIDs) > 8 {
		return nil, errVolume
	}
	out := []generated.AccessMeasurement{}
	for _, id := range in.ControlIDs {
		name, ok := strings.CutPrefix(id, "linux.volume-encryption:")
		if !ok {
			return nil, errVolume
		}
		var selected *generated.HostVolumeBinding
		for i := range in.Volumes {
			if in.Volumes[i].VolumeID == name {
				if selected != nil {
					return nil, errVolume
				}
				selected = &in.Volumes[i]
			}
		}
		if selected == nil || ValidateVolumeBinding(*selected) != nil || selected.HostID != in.HostID || selected.HostIdentityDigest != in.HostIdentityDigest {
			return nil, errVolume
		}
		facts, e := observeVolume(ctx, *selected)
		if e != nil {
			return nil, e
		}
		out = append(out, volumeMeasurement(*selected, in.ProfileLockDigest, "mapping", facts, "", time.Now()))
	}
	return out, nil
}
func volumeReadFile(name string, max int64) ([]byte, error) {
	f, e := os.Open(name)
	if e != nil {
		return nil, errVolume
	}
	defer f.Close()
	raw, e := io.ReadAll(io.LimitReader(f, max+1))
	if e != nil || int64(len(raw)) > max {
		return nil, errVolume
	}
	return raw, nil
}
func observeVolume(ctx context.Context, b generated.HostVolumeBinding) (string, error) {
	mounts, e := volumeReadFile("/proc/self/mountinfo", 2<<20)
	if e != nil {
		return "", e
	}
	mount, e := parseVolumeMount(mounts, b.MountPath)
	if e != nil || hostaction.Digest(mount) != b.MountBindingDigest {
		return "", errVolume
	}
	entries, e := os.ReadDir("/sys/block")
	if e != nil || len(entries) > 4096 {
		return "", errVolume
	}
	dm := ""
	for _, entry := range entries {
		n := entry.Name()
		if !strings.HasPrefix(n, "dm-") {
			continue
		}
		if _, e := strconv.ParseUint(strings.TrimPrefix(n, "dm-"), 10, 32); e != nil {
			continue
		}
		name, e := volumeReadFile("/sys/block/"+n+"/dm/name", 256)
		if e == nil && strings.TrimSpace(string(name)) == b.MapperName {
			if dm != "" {
				return "", errVolume
			}
			dm = n
		}
	}
	if dm == "" {
		return "", errVolume
	}
	sys := "/sys/block/" + dm
	dev, e := volumeReadFile(sys+"/dev", 64)
	if e != nil || strings.TrimSpace(string(dev)) != mount.Device {
		return "", errVolume
	}
	suspended, e := volumeReadFile(sys+"/dm/suspended", 16)
	if e != nil || strings.TrimSpace(string(suspended)) != "0" {
		return "", errVolume
	}
	dmUUID, e := volumeReadFile(sys+"/dm/uuid", 256)
	if e != nil || !strings.HasPrefix(strings.TrimSpace(string(dmUUID)), "CRYPT-LUKS2-"+strings.ReplaceAll(b.LUKSUUID, "-", "")+"-") {
		return "", errVolume
	}
	slaves, e := os.ReadDir(sys + "/slaves")
	if e != nil || len(slaves) != 1 || !safeName.MatchString(slaves[0].Name()) {
		return "", errVolume
	}
	slave := slaves[0].Name()
	slaveDev, e := volumeReadFile(sys+"/slaves/"+slave+"/dev", 64)
	expected := fmt.Sprintf("%d:%d", b.DeviceMajor, b.DeviceMinor)
	if e != nil || strings.TrimSpace(string(slaveDev)) != expected {
		return "", errVolume
	}
	fd, e := unix.Open("/dev/"+slave, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if e != nil {
		return "", errVolume
	}
	device := os.NewFile(uintptr(fd), "/dev/"+slave)
	defer device.Close()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFBLK || st.Uid != 0 || int64(unix.Major(uint64(st.Rdev))) != b.DeviceMajor || int64(unix.Minor(uint64(st.Rdev))) != b.DeviceMinor {
		return "", errVolume
	}
	var mountStat unix.Stat_t
	if unix.Stat(b.MountPath, &mountStat) != nil || fmt.Sprintf("%d:%d", unix.Major(uint64(mountStat.Dev)), unix.Minor(uint64(mountStat.Dev))) != mount.Device {
		return "", errVolume
	}
	raw := make([]byte, b.HeaderBytes)
	if _, e = device.ReadAt(raw, 0); e != nil {
		return "", errVolume
	}
	if _, e = parseVolumeHeader(raw, b.LUKSUUID); e != nil || hostaction.BytesDigest(raw) != b.HeaderDigest {
		return "", errVolume
	}
	sealed, e := sealedVolumeHeader(raw)
	if e != nil {
		return "", e
	}
	defer sealed.Close()
	toolFile, e := openVolumeProtected("/", "usr/sbin/cryptsetup", 0, false)
	if e != nil {
		return "", e
	}
	defer toolFile.Close()
	tool, e := readVolumeBounded(toolFile, 32<<20)
	if e != nil {
		return "", e
	}
	status, e := volumeCommand(ctx, tool, []string{"status", "--header", "/proc/self/fd/3", b.MapperName}, []*os.File{sealed}, 8192)
	if e != nil {
		return "", e
	}
	mapping, statusDevice, e := parseVolumeStatus(status, b.MapperName, b.DeviceMajor, b.DeviceMinor)
	if e != nil || volumeMappingDigest(mapping) != b.MappingDigest {
		return "", errVolume
	}
	var statusStat unix.Stat_t
	if unix.Stat(statusDevice, &statusStat) != nil || statusStat.Rdev != st.Rdev || statusStat.Mode&unix.S_IFMT != unix.S_IFBLK {
		return "", errVolume
	}
	meta, e := volumeCommand(ctx, tool, []string{"luksDump", "--dump-json-metadata", "/proc/self/fd/3"}, []*os.File{sealed}, 256<<10)
	if e != nil {
		return "", e
	}
	metadata, e := parseVolumeMetadata(meta, b.KeySlot, b.HeaderBytes)
	if e != nil || matchVolumeGeometry(mapping, metadata) != nil {
		return "", errVolume
	}
	// Re-read bindings after observation, including device inode and volatile map.
	current := make([]byte, b.HeaderBytes)
	if _, e = device.ReadAt(current, 0); e != nil || hostaction.BytesDigest(current) != b.HeaderDigest {
		return "", errVolume
	}
	status2, e := volumeCommand(ctx, tool, []string{"status", "--header", "/proc/self/fd/3", b.MapperName}, []*os.File{sealed}, 8192)
	if e != nil || string(status2) != string(status) {
		return "", errVolume
	}
	mounts2, e := volumeReadFile("/proc/self/mountinfo", 2<<20)
	if e != nil {
		return "", e
	}
	mount2, e := parseVolumeMount(mounts2, b.MountPath)
	if e != nil || mount2 != mount {
		return "", errVolume
	}
	var currentStat unix.Stat_t
	if unix.Stat(filepath.Join("/dev", slave), &currentStat) != nil || currentStat.Rdev != st.Rdev || currentStat.Ino != st.Ino || currentStat.Dev != st.Dev {
		return "", errVolume
	}
	suspended, e = volumeReadFile(sys+"/dm/suspended", 16)
	if e != nil || strings.TrimSpace(string(suspended)) != "0" {
		return "", errVolume
	}
	return hostaction.Digest(struct{ Header, Mapping, Mount, Metadata string }{b.HeaderDigest, b.MappingDigest, b.MountBindingDigest, hostaction.BytesDigest(meta)}), nil
}
