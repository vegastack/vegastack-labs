package debianbaseline

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	"github.com/vegastack/vegastack-labs/internal/strictjson"
)

var errVolume = errors.New("volume verification unavailable or binding changed")

const maximumVolumeHeader = 16 << 20

type volumeMetadata struct {
	Keyslots map[string]struct {
		Type string `json:"type"`
		Area struct {
			Type   string `json:"type"`
			Offset string `json:"offset"`
			Size   string `json:"size"`
		} `json:"area"`
	} `json:"keyslots"`
	Segments map[string]struct {
		Type       string   `json:"type"`
		Offset     string   `json:"offset"`
		Size       string   `json:"size"`
		Encryption string   `json:"encryption"`
		SectorSize int      `json:"sector_size"`
		Flags      []string `json:"flags"`
	} `json:"segments"`
	Digests map[string]struct {
		Type     string   `json:"type"`
		Keyslots []string `json:"keyslots"`
		Segments []string `json:"segments"`
	} `json:"digests"`
	Config struct {
		JSONSize     string              `json:"json_size"`
		KeyslotsSize string              `json:"keyslots_size"`
		Requirements map[string][]string `json:"requirements"`
	} `json:"config"`
}

// Parse only bounded metadata, never a dumped volume key. Cryptsetup supplies
// checksum/format validation; this projection additionally rejects unbound slots,
// reencryption, multiple data segments, and unsupported cipher geometry.
func parseVolumeMetadata(raw []byte, slot int64, expectedBytes int64) (volumeMetadata, error) {
	var m volumeMetadata
	if len(raw) == 0 || len(raw) > 256<<10 || slot < 0 || slot > 31 || expectedBytes > maximumVolumeHeader || strictjson.Scan(context.Background(), raw, strictjson.Limits{MaxDepth: 12}) != nil || json.Unmarshal(raw, &m) != nil {
		return m, errVolume
	}
	j, e := strconv.ParseInt(m.Config.JSONSize, 10, 64)
	if e != nil || j < 12288 || j > 4<<20 {
		return m, errVolume
	}
	h := j + 4096
	if h&(h-1) != 0 {
		return m, errVolume
	}
	k, e := strconv.ParseInt(m.Config.KeyslotsSize, 10, 64)
	if e != nil || k < 4096 || k%4096 != 0 || 2*h+k != expectedBytes || len(m.Config.Requirements) != 0 {
		return m, errVolume
	}
	if len(m.Segments) != 1 || len(m.Keyslots) > 32 || len(m.Digests) > 8 {
		return m, errVolume
	}
	seg, ok := m.Segments["0"]
	off, e := strconv.ParseInt(seg.Offset, 10, 64)
	if !ok || e != nil || off < expectedBytes || seg.Type != "crypt" || seg.Encryption != "aes-xts-plain64" || (seg.SectorSize != 512 && seg.SectorSize != 4096) || len(seg.Flags) != 0 {
		return m, errVolume
	}
	if seg.Size != "dynamic" {
		n, e := strconv.ParseInt(seg.Size, 10, 64)
		if e != nil || n <= 0 {
			return m, errVolume
		}
	}
	selected, ok := m.Keyslots[strconv.FormatInt(slot, 10)]
	if !ok || selected.Type != "luks2" {
		return m, errVolume
	}
	for _, s := range m.Keyslots {
		o, e := strconv.ParseInt(s.Area.Offset, 10, 64)
		n, e2 := strconv.ParseInt(s.Area.Size, 10, 64)
		if e != nil || e2 != nil || s.Type != "luks2" || s.Area.Type != "raw" || o < 2*h || n <= 0 || o > expectedBytes || n > expectedBytes-o {
			return m, errVolume
		}
	}
	bound := false
	for _, d := range m.Digests {
		if d.Type != "pbkdf2" {
			return m, errVolume
		}
		for _, s := range d.Keyslots {
			if s == strconv.FormatInt(slot, 10) {
				for _, v := range d.Segments {
					if v == "0" {
						bound = true
					}
				}
			}
		}
	}
	if !bound {
		return m, errVolume
	}
	return m, nil
}
func parseVolumeHeader(raw []byte, uuid string) (int64, error) {
	if len(raw) < 4096 || !bytes.Equal(raw[:6], []byte{'L', 'U', 'K', 'S', 0xba, 0xbe}) || binary.BigEndian.Uint16(raw[6:8]) != 2 {
		return 0, errVolume
	}
	size := binary.BigEndian.Uint64(raw[8:16])
	if size < 16384 || size > 4<<20 || size&(size-1) != 0 || strings.TrimRight(string(raw[168:208]), "\x00") != uuid {
		return 0, errVolume
	}
	return int64(size), nil
}
