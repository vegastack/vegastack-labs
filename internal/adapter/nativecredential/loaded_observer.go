package nativecredential

import (
	"context"
	"errors"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
)

type LoadedCredential struct {
	Name, MaterialVersion, CiphertextFingerprint string
	RestartObserved                              bool
	Device, Inode                                uint64
	UID, GID, Mode                               uint32
}
type LoadedObserver interface {
	ObserveLoaded(context.Context, credentialref.StepBinding) (LoadedCredential, error)
}
type NativeReceiptReader interface {
	ReadNativeLoadedReceipt(context.Context, credentialref.StepBinding) (credentialref.NativeLoadedReceipt, error)
}
type installedLoadedObserver struct {
	receipts   NativeReceiptReader
	recheck    func(context.Context, credentialref.NativeLoadedReceipt, credentialref.NativeConsumerBinding) error
	currentPID func() int
}

var errLoadedReceipt = errors.New("native loaded receipt unavailable")

func (o *installedLoadedObserver) ObserveLoaded(ctx context.Context, b credentialref.StepBinding) (LoadedCredential, error) {
	if o == nil || o.receipts == nil || o.recheck == nil || o.currentPID == nil || ctx == nil || ctx.Err() != nil || !credentialref.ValidBinding(b) {
		return LoadedCredential{}, errLoadedReceipt
	}
	r, err := o.receipts.ReadNativeLoadedReceipt(ctx, b)
	if err != nil || !credentialref.ValidNativeLoadedReceipt(r) || r.Binding.ReferenceID != b.ReferenceID || r.Binding.MaterialVersion != b.MaterialVersion || r.Binding.TargetID != b.TargetID || r.Binding.RecoveryEpoch != b.RecoveryEpoch || r.ConsumerID != b.ConsumerID {
		return LoadedCredential{}, errLoadedReceipt
	}
	reader, ok := r.Reader()
	if !ok || reader.LoadedName != credentialref.LoadedNameForVersion(b.ConsumerID, b.ReferenceID, b.MaterialVersion) || int(r.Proof.MainPID) != o.currentPID() || o.recheck(ctx, r, reader) != nil {
		return LoadedCredential{}, errLoadedReceipt
	}
	// A receipt remains valid only while its exact active database binding remains.
	again, err := o.receipts.ReadNativeLoadedReceipt(ctx, b)
	firstRaw, firstErr := credentialref.EncodeNativeLoadedReceipt(r)
	secondRaw, secondErr := credentialref.EncodeNativeLoadedReceipt(again)
	if err != nil || firstErr != nil || secondErr != nil || string(firstRaw) != string(secondRaw) || ctx.Err() != nil {
		return LoadedCredential{}, errLoadedReceipt
	}
	return LoadedCredential{Name: reader.LoadedName, MaterialVersion: r.Binding.MaterialVersion, CiphertextFingerprint: r.Proof.SourceFingerprint, RestartObserved: true, Device: r.Proof.CredentialDevice, Inode: r.Proof.CredentialInode, UID: r.Proof.CredentialUID, GID: r.Proof.CredentialGID, Mode: r.Proof.CredentialMode}, nil
}
