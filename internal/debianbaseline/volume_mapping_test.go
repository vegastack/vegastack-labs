package debianbaseline

import (
	"strings"
	"testing"
)

func TestVolumeMappingRejectsPlaintextOrAmbiguousMount(t *testing.T) {
	line := "36 22 253:0 / /srv/data rw,relatime - ext4 /dev/mapper/data rw\n"
	if _, e := parseVolumeMount([]byte(line), "/srv/data"); e != nil {
		t.Fatal(e)
	}
	for _, s := range []string{line + line, strings.Replace(line, "ext4", "overlay", 1), strings.Replace(line, "/srv/data", "/srv/other", 1)} {
		if _, e := parseVolumeMount([]byte(s), "/srv/data"); e == nil {
			t.Fatal("ambiguous/unsupported mount accepted")
		}
	}
	status := "/dev/mapper/data is active and is in use.\n  type: LUKS2\n  cipher: aes-xts-plain64\n  keysize: 512 bits\n  key location: keyring\n  device: /dev/vdb\n  sector size: 512\n  offset: 32768 sectors\n  size: 2048 sectors\n  mode: read/write\n"
	if _, _, e := parseVolumeStatus([]byte(status), "data", 8, 1); e != nil {
		t.Fatal(e)
	}
	for _, s := range []string{strings.Replace(status, "LUKS2", "PLAIN", 1), strings.Replace(status, "is active", "is inactive", 1), strings.Replace(status, "aes-xts-plain64", "null", 1), status + "type: LUKS2\n"} {
		if _, _, e := parseVolumeStatus([]byte(s), "data", 8, 1); e == nil {
			t.Fatal("unsafe active mapping accepted")
		}
	}
}

func TestVolumeGeometryJoinsHeaderToActiveMapping(t *testing.T) {
	meta, e := parseVolumeMetadata(volumeMetadataFixture(t), 0, 16<<20)
	if e != nil {
		t.Fatal(e)
	}
	base := volumeMapping{Offset: 32768, Size: 8192, SectorSize: 512, Cipher: "aes-xts-plain64"}
	if matchVolumeGeometry(base, meta) != nil {
		t.Fatal("matching dynamic geometry denied")
	}
	for _, mode := range []string{"offset", "size-overflow", "offset-overflow", "sector", "fixed-size"} {
		t.Run(mode, func(t *testing.T) {
			m := base
			v, e := parseVolumeMetadata(volumeMetadataFixture(t), 0, 16<<20)
			if e != nil {
				t.Fatal(e)
			}
			switch mode {
			case "offset":
				m.Offset = 65536
			case "size-overflow":
				m.Size = 1 << 62
			case "offset-overflow":
				m.Offset = 1 << 62
			case "sector":
				m.SectorSize = 4096
			case "fixed-size":
				seg := v.Segments["0"]
				seg.Size = "512"
				v.Segments["0"] = seg
			}
			if matchVolumeGeometry(m, v) == nil {
				t.Fatal("unbound active mapping accepted")
			}
		})
	}
	seg := meta.Segments["0"]
	seg.Size = "4194304"
	meta.Segments["0"] = seg
	if matchVolumeGeometry(base, meta) != nil {
		t.Fatal("matching fixed geometry denied")
	}
}
