package serverconfig

// Pinned restic release for local recovery-point creation (issue #106). The
// version is enforced structurally by matching one of the exact executable
// SHA-256 digests below; a matching digest implies the exact version, so the
// preflight never has to run a caller-selected binary to learn it.
const (
	ResticPinnedVersion = "0.19.1"

	// resticExecutableDigestAmd64 and resticExecutableDigestArm64 are the
	// SHA-256 digests of the official uncompressed linux restic 0.19.1
	// executables (amd64, arm64), verified from the pinned release on
	// 16-09-2026. They are executable digests, not archive digests.
	resticExecutableDigestAmd64 = "20d4142678d0d95ec11a4759def1b73fd9190abc9ca19e4b62d067c0b387e639"
	resticExecutableDigestArm64 = "2fb45ac6f9071b6f20eb883953a188f9e7c7cb6bbe43c67a2e47ada4e85ee7f0"
)

// ExpectedResticExecutableDigest returns the pinned lowercase-hex SHA-256 of the
// official restic 0.19.1 executable for a Go architecture, and whether that
// architecture is supported. Unsupported architectures fail closed.
func ExpectedResticExecutableDigest(goarch string) (string, bool) {
	switch goarch {
	case "amd64":
		return resticExecutableDigestAmd64, true
	case "arm64":
		return resticExecutableDigestArm64, true
	default:
		return "", false
	}
}
