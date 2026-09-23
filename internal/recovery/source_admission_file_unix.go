//go:build linux || darwin

package recovery

import (
	"crypto/ed25519"
	"os"
	"time"
)

const systemSourceAdmissionPath = "/etc/vsk-labs/recovery/source-admission.json"

// LoadSystemSourceAdmission verifies the administrator-signed, stable recovery
// source before a plan exists. The later witness package remains separately
// bound to the immutable plan and exact execution identifiers.
func LoadSystemSourceAdmission(expected SourceAdmissionExpectation) (SourceAdmission, error) {
	if os.Geteuid() == 0 || !validSourceAdmissionExpectation(expected) {
		return SourceAdmission{}, ErrWitnessUnavailable
	}
	root, err := readProtectedWitnessFile(systemAdminRootPath, 0, ed25519.PublicKeySize)
	if err != nil || len(root) != ed25519.PublicKeySize {
		return SourceAdmission{}, ErrWitnessUnavailable
	}
	raw, err := readProtectedWitnessFile(systemSourceAdmissionPath, 0, 65536)
	if err != nil {
		return SourceAdmission{}, ErrWitnessUnavailable
	}
	return ParseSignedSourceAdmission(raw, root, expected, time.Now().UTC())
}
