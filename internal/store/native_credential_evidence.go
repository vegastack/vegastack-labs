package store

import (
	"bytes"
	"context"
	"encoding/json"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
)

// NativeCredentialEvidence is limited to native-systemd consumers on the
// measured controller. It contains ciphertext/process metadata, never material.
type NativeCredentialEvidence struct {
	Controller        generated.NativeControllerIdentity
	Binding           credentialref.LifecycleBinding
	VersionID, Status string
	Verifications     []credentialref.ConsumerVerification
}

func (r *GateRepository) WithNativeControllerIdentity(v generated.NativeControllerIdentity) *GateRepository {
	if r == nil {
		return nil
	}
	copy := *r
	copy.nativeController = &v
	return &copy
}

func (r *GateRepository) nativeCredentialEvidence(ctx context.Context, q nativeQuery, e NativeProducerExecution, identity string) (*NativeCredentialEvidence, error) {
	c := r.nativeController
	if c == nil || !nativeContract(generated.SchemaIDNativeControllerIdentity, *c) || c.HostID != e.Reference.HostID || c.HostIdentityDigest != identity || e.Receipt.AdapterID != "core.credential" || e.Receipt.Status != "succeeded" {
		return nil, nativeError()
	}
	var current string
	var epoch int64
	if q.row(`SELECT instance_id,recovery_epoch FROM system_meta WHERE id=1`).Scan(&current, &epoch) != nil || current != c.ControllerInstanceID || epoch != e.Receipt.RecoveryEpoch {
		return nil, nativeError()
	}
	var raw []byte
	var digest string
	var b credentialref.LifecycleBinding
	if q.row(`SELECT binding_bytes,binding_digest FROM credential_lifecycle_bindings WHERE declaration_id=? AND declaration_revision=? AND operation_id=? AND recovery_epoch=?`, e.Plan.DeclarationID, e.Plan.Binding.DeclarationRevision-1, e.Receipt.OperationID, epoch).Scan(&raw, &digest) != nil || json.Unmarshal(raw, &b) != nil || !credentialref.ValidLifecycleBinding(b) || credentialref.LifecycleManifestDigestOf(b) != digest || draftLifecycleDigest(e.Plan.Extensions) != digest || b.ResolverID != "native-systemd" || b.OperationID != e.Receipt.OperationID || b.TargetID != e.Receipt.TargetID || b.StateRevision != e.Plan.Binding.StateRevision || b.RecoveryEpoch != epoch || b.CiphertextFingerprint != e.Receipt.ArtifactDigest {
		return nil, nativeError()
	}
	for _, reader := range b.NativeConsumers {
		if reader.HostMachineID != c.HostMachineID {
			return nil, nativeError()
		}
	}
	for _, reader := range b.NativeDeniedReaders {
		if reader.HostMachineID != c.HostMachineID {
			return nil, nativeError()
		}
	}
	canonical, _ := json.Marshal(b)
	if !bytes.Equal(raw, canonical) {
		return nil, nativeError()
	}
	out := &NativeCredentialEvidence{Controller: *c, Binding: b, Verifications: []credentialref.ConsumerVerification{}}
	var consumers []byte
	if q.row(`SELECT version_id,status,verified_consumers_bytes FROM credential_reference_versions WHERE reference_id=? AND material_version=? AND resolver_id='native-systemd' AND fingerprint=? AND target_id=? AND declaration_id=? AND declaration_revision=? AND plan_id=? AND plan_digest=? AND run_id=? AND step_id=? AND lease_id=? AND recovery_epoch=?`, b.ReferenceID, b.MaterialVersion, b.CiphertextFingerprint, b.TargetID, e.Plan.DeclarationID, e.Plan.Binding.DeclarationRevision, e.Reference.PlanID, e.Reference.PlanDigest, e.Reference.RunID, e.Reference.StepID, e.Reference.LeaseID, epoch).Scan(&out.VersionID, &out.Status, &consumers) != nil {
		return nil, nativeError()
	}
	rows, err := q.rows(`SELECT consumer_id,profile_id,role_id,material_version,ciphertext_fingerprint,evidence_digest,restart_observed,result,reason_code,native_receipt_bytes FROM credential_consumer_verifications WHERE reference_id=? AND version_id=? AND recovery_epoch=? ORDER BY consumer_id,result LIMIT 33`, b.ReferenceID, out.VersionID, epoch)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var v credentialref.ConsumerVerification
		var native []byte
		var restart bool
		if rows.Scan(&v.ConsumerID, &v.ProfileID, &v.RoleID, &v.MaterialVersion, &v.CiphertextFingerprint, &v.EvidenceDigest, &restart, &v.Result, &v.ReasonCode, &native) != nil {
			return nil, nativeError()
		}
		v.RestartObserved = restart
		if v.Result == "verified" {
			receipt, err := credentialref.DecodeNativeLoadedReceipt(native)
			if err != nil || receipt.PlanDigest != e.Reference.PlanDigest || receipt.RunID != e.Reference.RunID || receipt.StepID != e.Reference.StepID || receipt.ConsumerID != v.ConsumerID || hostaction.Digest(receipt.Binding) != hostaction.Digest(b) {
				return nil, nativeError()
			}
			reader, ok := receipt.Reader()
			if !ok || reader.HostMachineID != c.HostMachineID || reader.ProfileID != v.ProfileID || reader.RoleID != v.RoleID {
				return nil, nativeError()
			}
			v.NativeReceipt = &receipt
		} else if len(native) > 0 {
			return nil, nativeError()
		}
		out.Verifications = append(out.Verifications, v)
	}
	if rows.Err() != nil || len(out.Verifications) > 32 {
		return nil, nativeError()
	}
	var verified []string
	if json.Unmarshal(consumers, &verified) != nil {
		return nil, nativeError()
	}
	switch b.Action {
	case credentialref.ActionActivate, credentialref.ActionRotate:
		if out.Status != "active" || requireConsumerVerifications(b, out.Verifications, verified) != nil {
			return nil, nativeError()
		}
	case credentialref.ActionStage:
		if out.Status != "staged" || len(out.Verifications) != 0 {
			return nil, nativeError()
		}
	case credentialref.ActionRevoke:
		if out.Status != "revoked" || len(out.Verifications) != 0 {
			return nil, nativeError()
		}
	default:
		return nil, nativeError()
	}
	return out, nil
}
