package store

import (
	"strings"
	"testing"
)

func TestLiveVerificationRequiresExactSignedDependencyTrust(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	expected := []ExpectedDependencyRow{{DependencyID: "signature-a", Kind: "signature", Digest: digest}}
	proof := BackupDependencyTrustEvidence{DependencyID: "signature-a", Kind: "signature", Digest: digest,
		SourceKind: "registered-signed-artifact", PointID: "point-a", PolicyDigest: digest, SourceID: "source-a",
		ArtifactID: "artifact-a", BundleDigest: digest, TrustedRootReferenceID: "root-a", TrustRootDigest: digest,
		SignerIdentity: "https://example.invalid/signer", SignerIssuer: "https://issuer.example.invalid",
		SourceRevision: 1, StateRevision: 7, RecoveryEpoch: 2}
	if !exactStoredDependencyTrust(expected, []BackupDependencyTrustEvidence{proof}, "point-a", digest, 7, 2) {
		t.Fatal("exact signed dependency trust rejected")
	}
	for name, mutate := range map[string]func(*BackupDependencyTrustEvidence){
		"wrong point":    func(value *BackupDependencyTrustEvidence) { value.PointID = "point-b" },
		"wrong epoch":    func(value *BackupDependencyTrustEvidence) { value.RecoveryEpoch++ },
		"missing root":   func(value *BackupDependencyTrustEvidence) { value.TrustRootDigest = "" },
		"fixture source": func(value *BackupDependencyTrustEvidence) { value.SourceKind = "fixture" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := proof
			mutate(&changed)
			if exactStoredDependencyTrust(expected, []BackupDependencyTrustEvidence{changed}, "point-a", digest, 7, 2) {
				t.Fatal("invalid dependency trust accepted")
			}
		})
	}
	if exactStoredDependencyTrust(expected, nil, "point-a", digest, 7, 2) {
		t.Fatal("missing current signature trust accepted")
	}
}
