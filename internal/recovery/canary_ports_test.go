package recovery

import (
	"context"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type bundleReaderStub struct {
	bundle store.RecoveredAuthorityBundle
}

func (stub bundleReaderStub) RecoveredAuthorityBundle(context.Context, string) (store.RecoveredAuthorityBundle, string, error) {
	return stub.bundle, "sha256:" + strings.Repeat("e", 64), nil
}

type fenceRefresherStub struct {
	called   bool
	revision int64
	items    []generated.RestoreFenceItem
	digest   string
	binding  generated.RestoreBinding
}

func (stub *fenceRefresherStub) VerifyCanary(_ context.Context, binding generated.RestoreBinding, revision int64, items []generated.RestoreFenceItem) (FenceResult, error) {
	stub.called, stub.binding, stub.revision, stub.items = true, binding, revision, items
	return FenceResult{FenceSetDigest: stub.digest}, nil
}

func TestFreshFormerWriterCanaryReprobesExactRecoveredFence(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	request := CanaryRequest{PlanID: "plan-a", PlanDigest: digest, NewInstanceID: "instance-new", FenceSetDigest: "sha256:" + strings.Repeat("b", 64), RecoveryEpoch: 8, ExpectedStateRevision: 19, CanaryRunID: "canary-run", CanaryStepID: "canary-step", CanaryLeaseID: "canary-lease", CanaryChallengeID: "canary-challenge", CanaryReceiptID: "canary-receipt", ResponsibleHumanID: "human-a", PrincipalMethod: "local-os-peer"}
	items := []generated.RestoreFenceItem{{Boundary: "host-service"}}
	bundle := store.RecoveredAuthorityBundle{Status: "verification-required", Binding: generated.RestoreBinding{PlanID: request.PlanID, PlanDigest: request.PlanDigest, NewInstanceID: request.NewInstanceID, NextRecoveryEpoch: request.RecoveryEpoch, FenceSetDigest: request.FenceSetDigest, RecoveryRunID: "cutover-run", RecoveryStepID: "cutover-step", RecoveryLeaseID: "cutover-lease", RecoveryChallengeID: "cutover-challenge", RecoveryReceiptID: "cutover-receipt", CanaryRunID: request.CanaryRunID, CanaryStepID: request.CanaryStepID, CanaryLeaseID: request.CanaryLeaseID, CanaryChallengeID: request.CanaryChallengeID, CanaryReceiptID: request.CanaryReceiptID}, Request: generated.RestoreRequest{Fences: items}}
	fences := &fenceRefresherStub{digest: request.FenceSetDigest}
	verifier := FreshFormerWriterCanary{Restores: bundleReaderStub{bundle: bundle}, Fences: fences}
	if err := verifier.VerifyFormerWriterDenied(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if !fences.called || fences.revision != request.ExpectedStateRevision || len(fences.items) != 1 {
		t.Fatalf("fresh verifier call = %#v", fences)
	}
	if fences.binding.CanaryChallengeID != request.CanaryChallengeID || fences.binding.CanaryReceiptID != request.CanaryReceiptID || fences.binding.RecoveryChallengeID == fences.binding.CanaryChallengeID || fences.binding.RecoveryReceiptID == fences.binding.CanaryReceiptID {
		t.Fatalf("fresh verifier did not receive distinct canary custody IDs: %#v", fences.binding)
	}

	changed := request
	changed.FenceSetDigest = "sha256:" + strings.Repeat("c", 64)
	fences.called = false
	if err := verifier.VerifyFormerWriterDenied(context.Background(), changed); err == nil || fences.called {
		t.Fatalf("mismatched request reached fresh verifier: err=%v called=%v", err, fences.called)
	}
}
