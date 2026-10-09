package qualification

import (
	"net/netip"
	"slices"
	"time"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/debianaccess"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"golang.org/x/crypto/ssh"
)

func validateCredentialScenarioEvidence(es []ProducerExecution, observations []generated.NativeObservation) error {
	if len(es) != len(observations) {
		return ErrUnavailable
	}
	var witness *generated.NativeCredentialWitness
	var witnessAt time.Time
	var lifecycle []*NativeCredentialEvidence
	type policy struct {
		input generated.DebianAccessInput
		at    time.Time
	}
	var policies []policy
	for i, e := range es {
		if w := observations[i].Credential; w != nil {
			if !exactNativeJSON(generated.SchemaIDNativeCredentialWitness, *w) || witness != nil && hostaction.Digest(*witness) != hostaction.Digest(*w) {
				return ErrUnavailable
			}
			witness = w
			var err error
			witnessAt, err = time.Parse(time.RFC3339, observations[i].ObservedAt)
			if err != nil {
				return ErrUnavailable
			}
		}
		if e.Credential != nil {
			if e.Receipt.Status != "succeeded" || e.Receipt.AdapterID != "core.credential" || e.Credential.Controller.HostID != e.Reference.HostID {
				return ErrUnavailable
			}
			lifecycle = append(lifecycle, e.Credential)
			continue
		}
		r, err := producerAction(e)
		if err != nil || r.ActionID != "debian.access.apply" {
			return ErrUnavailable
		}
		in, err := debianaccess.DecodeInput([]byte(r.ActionInput))
		if err != nil || validateNativeAccessConfiguration(in, e.Result.ControlMeasurements, len(in.ContainerFlows) > 0) != nil {
			return ErrUnavailable
		}
		at, err := time.Parse(time.RFC3339, e.Result.ControlMeasurements[0].ObservedAt)
		if err != nil {
			return ErrUnavailable
		}
		policies = append(policies, policy{in, at})
	}
	if witness == nil || len(policies) != 2 || validateNativeCredentialChain(lifecycle) != nil {
		return ErrUnavailable
	}
	if policies[1].at.Before(policies[0].at) {
		policies[0], policies[1] = policies[1], policies[0]
	}
	before, after := policies[0], policies[1]
	if before.input.HostID != after.input.HostID || before.input.HostIdentityDigest != after.input.HostIdentityDigest || before.input.ProfileLockDigest != after.input.ProfileLockDigest || before.input.RenderedAccessDigest == after.input.RenderedAccessDigest {
		return ErrUnavailable
	}
	b, a, c := witness.PreviousBefore, witness.PreviousAfter, witness.CurrentAfter
	if validateCredentialSSH(b, "allowed", before.input) != nil || validateCredentialSSH(a, "denied", after.input) != nil || validateCredentialSSH(c, "allowed", after.input) != nil || b.PublicKeyDigest != a.PublicKeyDigest || a.PublicKeyDigest == c.PublicKeyDigest || b.User != a.User || a.User != c.User || b.SourceHostID != a.SourceHostID || a.SourceHostID != c.SourceHostID || b.SourceIdentityDigest != a.SourceIdentityDigest || a.SourceIdentityDigest != c.SourceIdentityDigest || b.SourceAddress != a.SourceAddress || a.SourceAddress != c.SourceAddress || b.NamespaceDigest != a.NamespaceDigest || a.NamespaceDigest != c.NamespaceDigest || b.DestinationAddress != a.DestinationAddress || a.DestinationAddress != c.DestinationAddress || b.DestinationPort != a.DestinationPort || a.DestinationPort != c.DestinationPort {
		return ErrUnavailable
	}
	if !accountHasNativeKey(before.input, b.User, b.PublicKeyDigest) || accountHasNativeKey(after.input, a.User, a.PublicKeyDigest) || !accountHasNativeKey(after.input, c.User, c.PublicKeyDigest) {
		return ErrUnavailable
	}
	bt, e1 := time.Parse(time.RFC3339, b.ObservedAt)
	at, e2 := time.Parse(time.RFC3339, a.ObservedAt)
	ct, e3 := time.Parse(time.RFC3339, c.ObservedAt)
	if e1 != nil || e2 != nil || e3 != nil || bt.Before(before.at) || !bt.Before(after.at) || at.Before(after.at) || ct.Before(after.at) || witnessAt.Before(at) || witnessAt.Before(ct) || witnessAt.Sub(at) > 30*time.Second || witnessAt.Sub(ct) > 30*time.Second {
		return ErrUnavailable
	}
	return nil
}

func validateNativeCredentialChain(values []*NativeCredentialEvidence) error {
	// Two staged versions, actual first activation, rotation, and old revocation.
	if len(values) != 5 {
		return ErrUnavailable
	}
	var first, current, revoked *NativeCredentialEvidence
	stages := map[string]*NativeCredentialEvidence{}
	var reference, controller string
	for _, v := range values {
		if v == nil || !credentialref.ValidLifecycleBinding(v.Binding) || v.Binding.ResolverID != "native-systemd" {
			return ErrUnavailable
		}
		if reference == "" {
			reference = v.Binding.ReferenceID
			controller = hostaction.Digest(v.Controller)
		} else if reference != v.Binding.ReferenceID || controller != hostaction.Digest(v.Controller) {
			return ErrUnavailable
		}
		switch v.Binding.Action {
		case credentialref.ActionStage:
			if v.Status != "staged" || stages[v.Binding.MaterialVersion] != nil {
				return ErrUnavailable
			}
			stages[v.Binding.MaterialVersion] = v
		case credentialref.ActionActivate:
			if first != nil || v.Status != "active" {
				return ErrUnavailable
			}
			first = v
		case credentialref.ActionRotate:
			if current != nil || v.Status != "active" {
				return ErrUnavailable
			}
			current = v
		case credentialref.ActionRevoke:
			if revoked != nil || v.Status != "revoked" {
				return ErrUnavailable
			}
			revoked = v
		default:
			return ErrUnavailable
		}
	}
	if first == nil || current == nil || revoked == nil || current.Binding.PriorMaterialVersion == nil || *current.Binding.PriorMaterialVersion != first.Binding.MaterialVersion || current.Binding.MaterialVersion == first.Binding.MaterialVersion || revoked.Binding.MaterialVersion != first.Binding.MaterialVersion || first.Binding.CiphertextFingerprint == current.Binding.CiphertextFingerprint || revoked.Binding.CiphertextFingerprint != first.Binding.CiphertextFingerprint || first.Binding.StateRevision >= current.Binding.StateRevision || current.Binding.StateRevision >= revoked.Binding.StateRevision {
		return ErrUnavailable
	}
	for _, active := range []*NativeCredentialEvidence{first, current} {
		stage := stages[active.Binding.MaterialVersion]
		if stage == nil || stage.Binding.CiphertextFingerprint != active.Binding.CiphertextFingerprint || stage.Binding.StateRevision >= active.Binding.StateRevision {
			return ErrUnavailable
		}
	}
	before := map[string]credentialref.NativeInvocationMetadata{}
	for _, v := range first.Verifications {
		if v.Result == "verified" {
			if v.NativeReceipt == nil || !credentialref.ValidNativeLoadedReceipt(*v.NativeReceipt) {
				return ErrUnavailable
			}
			before[v.ConsumerID] = v.NativeReceipt.Proof
		}
	}
	if len(before) == 0 {
		return ErrUnavailable
	}
	checked := 0
	for _, v := range current.Verifications {
		if v.Result == "verified" {
			old, ok := before[v.ConsumerID]
			if !ok || v.NativeReceipt == nil || !credentialref.ValidNativeLoadedReceipt(*v.NativeReceipt) {
				return ErrUnavailable
			}
			now := v.NativeReceipt.Proof
			if old.InvocationID == now.InvocationID || old.MainPID == now.MainPID && old.ProcessStartTicks == now.ProcessStartTicks || old.SourceFingerprint == now.SourceFingerprint {
				return ErrUnavailable
			}
			checked++
		}
	}
	if checked != len(before) {
		return ErrUnavailable
	}
	return nil
}

func accountHasNativeKey(in generated.DebianAccessInput, user, digest string) bool {
	for _, account := range in.Accounts {
		if account.Name == user {
			for _, raw := range account.PublicKeys {
				key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(raw))
				if err == nil && hostaction.BytesDigest(key.Marshal()) == digest {
					return true
				}
			}
		}
	}
	return false
}
func validateCredentialSSH(o generated.NativeSshObservation, outcome string, in generated.DebianAccessInput) error {
	if !o.HostKeyVerified || len(o.Outcomes) != 1 || o.Outcomes[0] != outcome || o.PublicKeyDigest == "" || o.DestinationHostID != in.HostID || o.DestinationIdentityDigest != in.HostIdentityDigest || !slices.Contains(in.SSHUsers, o.User) {
		return ErrUnavailable
	}
	address, err := netip.ParseAddr(o.SourceAddress)
	if err != nil {
		return ErrUnavailable
	}
	allowed := false
	for _, raw := range in.SSHSourcePrefixes {
		p, err := netip.ParsePrefix(raw)
		allowed = allowed || err == nil && p.Contains(address)
	}
	if !allowed {
		return ErrUnavailable
	}
	return nil
}
