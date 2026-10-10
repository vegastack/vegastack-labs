package debianbaseline

import (
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
)

func TestVolumeRecoveryRotationKeepsExactPhysicalBinding(t *testing.T) {
	d := hostaction.Digest("fixture-original")
	prior := generated.VolumeRecoveryInput{HostID: "custodian", HostIdentityDigest: d, ProfileID: "debian-13-amd64", ProfileLockDigest: d, RecoveryReferenceID: "volume", RecoveryMaterialVersion: "initial", PriorVolumeReceiptDigest: d,
		Binding: generated.HostVolumeBinding{HostID: "subject", HostIdentityDigest: d, ControlHostID: "controller", ControlHostIdentityDigest: d, VolumeID: "data", HeaderDigest: d, MappingDigest: d, MountBindingDigest: d, KeySlot: 0, RecoveryReferenceDigest: d, DeclarationID: "volume-declaration", DeclarationRevision: 1}}
	current := prior
	current.RecoveryMaterialVersion = "current"
	current.Binding.RecoveryReferenceDigest = hostaction.Digest("fixture-current-policy")
	current.Binding.DeclarationRevision = 2
	current.PriorVolumeReceiptDigest = hostaction.Digest("fixture-current-mapping-receipt")
	for _, variant := range []string{"own", "same-revision", "older-revision", "other-declaration", "same-receipt", "same-material", "same-policy", "header", "mapping", "mount", "slot", "subject", "controller", "custodian", "epoch", "profile", "reference"} {
		t.Run(variant, func(t *testing.T) {
			in := current
			switch variant {
			case "same-revision":
				in.Binding.DeclarationRevision = prior.Binding.DeclarationRevision
			case "older-revision":
				in.Binding.DeclarationRevision = 0
			case "other-declaration":
				in.Binding.DeclarationID = "other"
			case "same-receipt":
				in.PriorVolumeReceiptDigest = prior.PriorVolumeReceiptDigest
			case "same-material":
				in.RecoveryMaterialVersion = prior.RecoveryMaterialVersion
			case "same-policy":
				in.Binding.RecoveryReferenceDigest = prior.Binding.RecoveryReferenceDigest
			case "header":
				in.Binding.HeaderDigest = hostaction.Digest("other-header")
			case "mapping":
				in.Binding.MappingDigest = hostaction.Digest("other-mapping")
			case "mount":
				in.Binding.MountBindingDigest = hostaction.Digest("other-mount")
			case "slot":
				in.Binding.KeySlot++
			case "subject":
				in.Binding.HostID = "other-subject"
			case "controller":
				in.Binding.ControlHostID = "other-controller"
			case "custodian":
				in.HostID = "other-custodian"
			case "epoch":
				in.Binding.RecoveryEpoch++
			case "profile":
				in.ProfileLockDigest = hostaction.Digest("other-profile")
			case "reference":
				in.RecoveryReferenceID = "other-reference"
			}
			if VolumeRecoveryRotationMatches(in, prior) != (variant == "own") {
				t.Fatal("rotation physical/lineage boundary changed", variant)
			}
		})
	}
}
