//go:build linux

package nativecredential

import (
	"context"
	"errors"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"os"
	"testing"
)

type currentLoadedAuthority struct {
	deny   bool
	probes int
}

func (*currentLoadedAuthority) Restart(context.Context, string) (RestartReceipt, error) {
	return RestartReceipt{}, errors.New("observation must not restart")
}
func (a *currentLoadedAuthority) Probe(context.Context, AccessProbeRequest) (AccessProbeResult, error) {
	a.probes++
	if a.deny {
		return AccessProbeResult{Status: AccessProbeDenied}, nil
	}
	return AccessProbeResult{Status: AccessProbeOpened}, nil
}

func TestLoadedObserverReobservesUnchangedSourceAfterRestart(t *testing.T) {
	old, b := loadedReceiptFixture()
	for _, kind := range []string{"current-restart", "changed-source-inode", "changed-source-digest", "foreign-current-pid", "denied-reader-opened", "revoked-after-observation", "invalid-current-proof"} {
		t.Run(kind, func(t *testing.T) {
			seq := &receiptSequence{receipt: old}
			proof := old.Proof
			proof.MainPID = uint32(os.Getpid())
			proof.InvocationID = "cccccccccccccccccccccccccccccccc"
			proof.CredentialInode++
			proof.ProcessStartTicks++
			authority := &currentLoadedAuthority{deny: true}
			switch kind {
			case "changed-source-inode":
				proof.SourceInode++
			case "changed-source-digest":
				proof.SourceFingerprint = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
			case "foreign-current-pid":
				proof.MainPID++
			case "denied-reader-opened":
				authority.deny = false
			case "revoked-after-observation":
				seq.revoke = true
			case "invalid-current-proof":
				proof.CredentialMode = 0100666
			}
			v := &NativeLifecycleVerifier{Authority: authority, policy: func(credentialref.LifecycleBinding) error { return nil }, current: func(context.Context, credentialref.LifecycleBinding, credentialref.NativeConsumerBinding) (NativeInvocationProof, error) {
				return proof, nil
			}, recheck: func(_ context.Context, _ credentialref.LifecycleBinding, _ credentialref.NativeConsumerBinding, p NativeInvocationProof) error {
				if p != proof {
					return errors.New("not the current observed invocation")
				}
				return nil
			}}
			observer, err := NewLoadedObserver(v, seq)
			if err != nil {
				t.Fatal(err)
			}
			got, err := observer.ObserveLoaded(context.Background(), b)
			if kind == "current-restart" {
				if err != nil || got.Inode != proof.CredentialInode || authority.probes != 1 || seq.calls != 2 {
					t.Fatal("unchanged key unavailable after current native restart", got, err)
				}
			} else if err == nil {
				t.Fatal("unverified restart observation accepted")
			}
		})
	}
}
