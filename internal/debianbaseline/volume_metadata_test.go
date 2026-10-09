package debianbaseline

import (
	"encoding/binary"
	"encoding/json"
	"testing"
)

func volumeMetadataFixture(t *testing.T) []byte {
	t.Helper()
	v := map[string]any{
		"keyslots": map[string]any{"0": map[string]any{"type": "luks2", "area": map[string]any{"type": "raw", "offset": "32768", "size": "258048"}}},
		"segments": map[string]any{"0": map[string]any{"type": "crypt", "offset": "16777216", "size": "dynamic", "encryption": "aes-xts-plain64", "sector_size": 512}},
		"digests":  map[string]any{"0": map[string]any{"type": "pbkdf2", "keyslots": []string{"0"}, "segments": []string{"0"}}},
		"config":   map[string]any{"json_size": "12288", "keyslots_size": "16744448"},
	}
	raw, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return raw
}
func TestVolumeMetadataRequiresBoundSelectedSlot(t *testing.T) {
	raw := volumeMetadataFixture(t)
	if _, e := parseVolumeMetadata(raw, 0, 16<<20); e != nil {
		t.Fatal(e)
	}
	for _, change := range []func(map[string]any){
		func(v map[string]any) { v["digests"].(map[string]any)["0"].(map[string]any)["segments"] = []string{} },
		func(v map[string]any) { v["segments"].(map[string]any)["0"].(map[string]any)["type"] = "linear" },
		func(v map[string]any) { v["config"].(map[string]any)["keyslots_size"] = "999999999" },
		func(v map[string]any) {
			v["keyslots"].(map[string]any)["0"].(map[string]any)["area"].(map[string]any)["offset"] = "4"
		},
	} {
		var v map[string]any
		_ = json.Unmarshal(raw, &v)
		change(v)
		changed, _ := json.Marshal(v)
		if _, e := parseVolumeMetadata(changed, 0, 16<<20); e == nil {
			t.Fatal("unsafe metadata accepted")
		}
	}
	if _, e := parseVolumeMetadata(raw, 1, 16<<20); e == nil {
		t.Fatal("missing selected slot accepted")
	}
}
func TestVolumeHeaderBoundsAndIdentity(t *testing.T) {
	raw := make([]byte, 4096)
	copy(raw, []byte{'L', 'U', 'K', 'S', 0xba, 0xbe})
	binary.BigEndian.PutUint16(raw[6:8], 2)
	binary.BigEndian.PutUint64(raw[8:16], 16384)
	copy(raw[168:208], "11111111-2222-3333-4444-555555555555")
	if _, e := parseVolumeHeader(raw, "11111111-2222-3333-4444-555555555555"); e != nil {
		t.Fatal(e)
	}
	if _, e := parseVolumeHeader(raw, "aaaaaaaa-2222-3333-4444-555555555555"); e == nil {
		t.Fatal("wrong UUID accepted")
	}
	binary.BigEndian.PutUint64(raw[8:16], 1<<30)
	if _, e := parseVolumeHeader(raw, "11111111-2222-3333-4444-555555555555"); e == nil {
		t.Fatal("oversized metadata accepted")
	}
}
