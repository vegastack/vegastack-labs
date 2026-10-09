package debianbaseline

import (
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"strconv"
	"strings"
)

type volumeMount struct{ ID, Parent, Device, Root, Path, Options, FSType, Source string }

func parseVolumeMount(raw []byte, want string) (volumeMount, error) {
	var found volumeMount
	count := 0
	if len(raw) > 2<<20 {
		return found, errVolume
	}
	decode := strings.NewReplacer("\\040", " ", "\\011", "\t", "\\012", "\n", "\\134", "\\")
	for _, line := range strings.Split(string(raw), "\n") {
		f := strings.Fields(line)
		if len(f) < 10 || decode.Replace(f[4]) != want {
			continue
		}
		cut := -1
		for i := 6; i < len(f); i++ {
			if f[i] == "-" {
				cut = i
				break
			}
		}
		if cut < 6 || len(f) < cut+4 {
			return found, errVolume
		}
		count++
		found = volumeMount{ID: f[0], Parent: f[1], Device: f[2], Root: decode.Replace(f[3]), Path: decode.Replace(f[4]), Options: f[5], FSType: f[cut+1], Source: decode.Replace(f[cut+2])}
	}
	if count != 1 || found.FSType != "ext4" && found.FSType != "xfs" && found.FSType != "btrfs" {
		return found, errVolume
	}
	return found, nil
}

type volumeMapping struct {
	Name, Cipher                                       string
	DeviceMajor, DeviceMinor, Offset, Size, SectorSize int64
}

func parseVolumeStatus(raw []byte, name string, major, minor int64) (volumeMapping, string, error) {
	m := volumeMapping{Name: name, DeviceMajor: major, DeviceMinor: minor}
	if len(raw) > 8192 {
		return m, "", errVolume
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) < 2 || !strings.Contains(lines[0], " is active") || strings.Contains(lines[0], "inactive") {
		return m, "", errVolume
	}
	fields := map[string]string{}
	for _, line := range lines[1:] {
		k, v, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok || fields[k] != "" {
			return m, "", errVolume
		}
		fields[k] = strings.TrimSpace(v)
	}
	if fields["type"] != "LUKS2" || fields["cipher"] != "aes-xts-plain64" || fields["keysize"] != "512 bits" || fields["mode"] != "read/write" && fields["mode"] != "readonly" {
		return m, "", errVolume
	}
	m.Cipher = fields["cipher"]
	number := func(key, suffix string) (int64, error) {
		s := strings.TrimSuffix(fields[key], suffix)
		n, e := strconv.ParseInt(s, 10, 64)
		if e != nil || n < 0 {
			return 0, errVolume
		}
		return n, nil
	}
	var e error
	m.Offset, e = number("offset", " sectors")
	if e != nil {
		return m, "", e
	}
	m.Size, e = number("size", " sectors")
	if e != nil || m.Size == 0 {
		return m, "", errVolume
	}
	m.SectorSize, e = number("sector size", "")
	if e != nil || m.SectorSize != 512 && m.SectorSize != 4096 {
		return m, "", errVolume
	}
	device := fields["device"]
	if !strings.HasPrefix(device, "/dev/") || strings.ContainsAny(device, "\x00\r\n\t ") {
		return m, "", errVolume
	}
	return m, device, nil
}
func volumeMappingDigest(m volumeMapping) string { return hostaction.Digest(m) }
