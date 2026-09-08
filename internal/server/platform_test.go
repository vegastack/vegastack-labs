package server

import "testing"

func TestParseOSReleaseRequiresExactDebianMajor(t *testing.T) {
	platform, err := parseOSRelease([]byte("ID=debian\nVERSION_ID=\"13\"\n"), "linux", "amd64")
	if err != nil || platform != (Platform{OS: "linux", Architecture: "amd64", Distribution: "debian", Major: 13}) {
		t.Fatalf("parseOSRelease() = (%#v, %v)", platform, err)
	}
	for _, content := range []string{"", "ID=ubuntu\nVERSION_ID=13\n", "ID=debian\nVERSION_ID=bookworm\n", "ID=debian\nVERSION_ID=13.1\n"} {
		if _, err := parseOSRelease([]byte(content), "linux", "amd64"); err == nil {
			t.Fatalf("parseOSRelease(%q) succeeded", content)
		}
	}
}
