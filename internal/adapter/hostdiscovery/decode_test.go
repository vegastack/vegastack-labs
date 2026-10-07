package hostdiscovery

import (
	"bytes"
	"testing"
)

func TestDecodeRejectsOversizedOutput(t *testing.T) {
	if _, err := Decode("os-release", bytes.Repeat([]byte("x"), 65537)); err == nil {
		t.Fatal("oversized remote data accepted")
	}
}
func TestDecodeFactsAndRejectAmbiguity(t *testing.T) {
	for _, tc := range []struct {
		op, raw string
		valid   bool
	}{
		{"os-release", "ID=debian\nVERSION_ID=\"13\"\n", true}, {"os-release", "ID=debian\nID=ubuntu\n", false},
		{"cpu-online", "0-3,6\n", true}, {"cpu-online", "0-3,2\n", false}, {"cpu-online", "0-9999999999", false},
		{"memory", "MemTotal: 1024 kB\n", true}, {"memory", "MemTotal: 9223372036854775807 kB", false},
		{"architecture", "x86_64\n", true}, {"machine-id", "0123456789abcdef0123456789abcdef\n", true},
		{"block-devices", `{"blockdevices":[{"name":"vda","type":"disk","size":1024}]}`, true},
		{"block-devices", `{"blockdevices":[],"blockdevices":[]}`, false},
		{"unknown", "canary-secret", false},
	} {
		t.Run(tc.op+tc.raw, func(t *testing.T) {
			facts, err := Decode(tc.op, []byte(tc.raw))
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v, error=%v", tc.valid, err)
			}
			if tc.valid && len(facts) == 0 {
				t.Fatal("no decoded facts")
			}
		})
	}
}
