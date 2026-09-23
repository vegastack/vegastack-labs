//go:build !linux

package localbackup

// Unsupported platforms have no protected local dependency trust source.
func NewProtectedLocalDependencyTrust() DependencyTrustVerifier { return nil }
