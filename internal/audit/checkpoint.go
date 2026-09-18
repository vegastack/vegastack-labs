package audit

import (
	"context"
	"encoding/base64"
	"encoding/json"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
)

const checkpointDomain = "vegastack-labs.dev/audit-checkpoint-signing/v1"

type PublicKey struct {
	ID    string
	Bytes []byte
}

type Signature struct {
	PublicKeyID string
	Bytes       []byte
	Digest      Fingerprint
}

type ExportReceipt struct {
	CheckpointID  string
	ExactPath     string
	PayloadDigest Fingerprint
	ReceiptDigest Fingerprint
}

type IndependentCheckpoint struct {
	CheckpointID    string
	InstanceID      string
	RecoveryEpoch   int64
	LastEventID     EventID
	LastSequence    int64
	ChainDigest     Fingerprint
	SignerReference credentialref.Reference
	MaterialVersion string
	Namespace       string
	SignedDigest    Fingerprint
	Signature       Signature
	ExportReceipt   Fingerprint
	IndependentRead Fingerprint
}

type CheckpointSigner interface {
	Sign(context.Context, Fingerprint, credentialref.Reference) (Signature, error)
	Verify(Fingerprint, Signature, PublicKey) error
}

func CheckpointDigest(chain ChainRange, instanceID string, epoch int64, signer credentialref.Reference, materialVersion, namespace string) (Fingerprint, error) {
	if len(chain.Links) == 0 || chain.FirstEventID <= 0 || chain.LastEventID < chain.FirstEventID || !ValidFingerprint(chain.RangeDigest) || !validToken(instanceID, 128) || epoch < 0 || !validToken(signer.ID, 128) || !validToken(signer.Consumer, 128) || !validToken(materialVersion, 128) || !validToken(namespace, 128) {
		return "", errInvalid
	}
	return CheckpointBindingDigest(chain.FirstEventID, chain.LastEventID, chain.Links[0].SegmentSequence, chain.Links[len(chain.Links)-1].SegmentSequence, chain.RangeDigest, instanceID, epoch, signer, materialVersion, namespace)
}

func CheckpointBindingDigest(firstEventID, lastEventID EventID, firstSequence, lastSequence int64, chainDigest Fingerprint, instanceID string, epoch int64, signer credentialref.Reference, materialVersion, namespace string) (Fingerprint, error) {
	if firstEventID <= 0 || lastEventID < firstEventID || firstSequence <= 0 || lastSequence < firstSequence || !ValidFingerprint(chainDigest) || !validToken(instanceID, 128) || epoch < 0 || !validToken(signer.ID, 128) || !validToken(signer.Consumer, 128) || !validToken(materialVersion, 128) || !validToken(namespace, 128) {
		return "", errInvalid
	}
	data, err := json.Marshal(struct {
		Domain          string      `json:"domain"`
		InstanceID      string      `json:"instanceId"`
		RecoveryEpoch   int64       `json:"recoveryEpoch"`
		FirstEventID    EventID     `json:"firstEventId"`
		LastEventID     EventID     `json:"lastEventId"`
		FirstSequence   int64       `json:"firstSegmentSequence"`
		LastSequence    int64       `json:"lastSegmentSequence"`
		ChainDigest     Fingerprint `json:"chainDigest"`
		SignerReference string      `json:"signerReferenceId"`
		SignerConsumer  string      `json:"signerConsumerId"`
		MaterialVersion string      `json:"signerMaterialVersion"`
		Namespace       string      `json:"exportNamespace"`
	}{checkpointDomain, instanceID, epoch, firstEventID, lastEventID, firstSequence, lastSequence, chainDigest, signer.ID, signer.Consumer, materialVersion, namespace})
	if err != nil {
		return "", errInvalid
	}
	return hashChainBytes(data), nil
}

func SignatureDigest(signature []byte) Fingerprint {
	return hashChainBytes(signature)
}

func EncodeSignedCheckpoint(checkpoint IndependentCheckpoint) ([]byte, error) {
	if !validToken(checkpoint.CheckpointID, 128) || !validToken(checkpoint.InstanceID, 128) || checkpoint.RecoveryEpoch < 0 || checkpoint.LastEventID <= 0 || checkpoint.LastSequence <= 0 || !ValidFingerprint(checkpoint.ChainDigest) || !validToken(checkpoint.SignerReference.ID, 128) || !validToken(checkpoint.SignerReference.Consumer, 128) || !validToken(checkpoint.MaterialVersion, 128) || !validToken(checkpoint.Namespace, 128) || !ValidFingerprint(checkpoint.SignedDigest) || !validToken(checkpoint.Signature.PublicKeyID, 128) || len(checkpoint.Signature.Bytes) == 0 || checkpoint.Signature.Digest != SignatureDigest(checkpoint.Signature.Bytes) {
		return nil, errInvalid
	}
	return json.Marshal(struct {
		CheckpointID          string      `json:"checkpointId"`
		InstanceID            string      `json:"instanceId"`
		RecoveryEpoch         int64       `json:"recoveryEpoch"`
		LastEventID           EventID     `json:"lastEventId"`
		LastSequence          int64       `json:"lastSegmentSequence"`
		ChainDigest           Fingerprint `json:"chainDigest"`
		PublicKeyID           string      `json:"publicKeyId"`
		SignerReferenceID     string      `json:"signerReferenceId"`
		SignerConsumerID      string      `json:"signerConsumerId"`
		SignerMaterialVersion string      `json:"signerMaterialVersion"`
		Namespace             string      `json:"namespace"`
		SignedDigest          Fingerprint `json:"signedDigest"`
		Signature             string      `json:"signature"`
	}{checkpoint.CheckpointID, checkpoint.InstanceID, checkpoint.RecoveryEpoch, checkpoint.LastEventID, checkpoint.LastSequence, checkpoint.ChainDigest, checkpoint.Signature.PublicKeyID, checkpoint.SignerReference.ID, checkpoint.SignerReference.Consumer, checkpoint.MaterialVersion, checkpoint.Namespace, checkpoint.SignedDigest, base64.StdEncoding.EncodeToString(checkpoint.Signature.Bytes)})
}
