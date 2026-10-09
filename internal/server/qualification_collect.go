package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	transport "github.com/vegastack/vegastack-labs/internal/adapter/hostaction"
	"time"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/qualification"
	"github.com/vegastack/vegastack-labs/internal/store"
)

func (s *nativeQualificationService) CollectDraft(ctx context.Context, in generated.NativeCollectRequest, a audit.Attribution) (store.GateDraft, []generated.ScenarioResult, error) {
	var zero store.GateDraft
	deny := func() (store.GateDraft, []generated.ScenarioResult, error) {
		return zero, nil, failure.New(generated.ErrorCodePrerequisiteBlocked, "native-qualification", false)
	}
	if s == nil || s.authority == nil || s.gates == nil {
		return deny()
	}
	scope, err := qualification.LoadServerScope(ctx)
	if err != nil || hostaction.Digest(scope) != in.ScopeDigest || scope.ProfileID != in.ProfileID || len(qualification.StageScenarios(in.Stage)) == 0 {
		return deny()
	}
	gates := s.gates
	var controller *generated.NativeControllerIdentity
	for _, ref := range in.Producers {
		if ref.ScenarioID == "native-credential-lifecycle" {
			authority, err := s.authority.CurrentAuthority(ctx)
			if err != nil {
				return deny()
			}
			measured, err := qualification.MeasureControllerIdentity(ctx, scope, authority.InstanceID)
			if err != nil {
				return deny()
			}
			controller = &measured
			gates = gates.WithNativeControllerIdentity(measured)
			break
		}
	}
	snapshot, err := gates.ResolveNativeProducers(ctx, in)
	if err != nil {
		return zero, nil, err
	}
	if !nativeCollectorAuthority(scope, snapshot) || snapshot.Revision.StateRevision != in.ExpectedStateRevision || snapshot.Revision.RecoveryEpoch != in.RecoveryEpoch || snapshot.Digest == "" || len(snapshot.Producers) != len(in.Producers) || len(snapshot.Executions) != len(in.Producers) {
		return deny()
	}
	guests := map[string]generated.QualificationGuest{}
	for _, guest := range scope.Guests {
		if _, exists := guests[guest.HostID]; exists {
			return deny()
		}
		guests[guest.HostID] = guest
	}
	observer, err := qualification.OpenNativeObserver(ctx, scope)
	if err != nil {
		return deny()
	}
	defer observer.Close()
	observations := make([]generated.NativeObservation, 0, len(snapshot.Producers))
	executions := make([]qualification.ProducerExecution, 0, len(snapshot.Executions))
	for _, execution := range snapshot.Executions {
		if !store.NativeExecutionProfileMatches(execution, scope.ProfileID, scope.ProfileLockDigest) {
			return deny()
		}
		projected := qualification.ProducerExecution{Reference: execution.Reference, Plan: execution.Plan, Receipt: execution.Receipt, Result: execution.Result}
		if v := execution.Credential; v != nil {
			projected.Credential = &qualification.NativeCredentialEvidence{Controller: v.Controller, Binding: v.Binding, VersionID: v.VersionID, Status: v.Status, Verifications: v.Verifications}
		}
		if v := execution.ReplacementRecovery; v != nil {
			projected.ReplacementRecovery = &qualification.ReplacementRecoveryEvidence{CurrentProfileID: v.CurrentProfileID, CurrentProfileLockDigest: v.CurrentProfileLockDigest, Binding: v.Binding, Replacement: v.Replacement, Continuity: v.Continuity, CanaryDigest: v.CanaryDigest, CanaryRunID: v.CanaryRunID, CanaryEventID: v.CanaryEventID, VerifiedAt: v.VerifiedAt}
		}
		if v := execution.ControlSetupAuthority; v != nil {
			projected.ControlSetupAuthority = &qualification.ControlSetupAuthority{SetupID: v.SetupID, RequestDigest: v.RequestDigest, ReviewDigest: v.ReviewDigest, InstanceID: v.InstanceID, HumanID: v.HumanID, AuthorityID: v.AuthorityID, InitializedAt: v.InitializedAt, RecoveryEpoch: v.RecoveryEpoch, InitialEventID: v.InitialEventID, InitialEventDigest: v.InitialEventDigest, InitialChainDigest: v.InitialChainDigest, VerifiedRestoreBinding: v.VerifiedRestoreBinding}
		}
		executions = append(executions, projected)
	}
	for ordinal, producer := range snapshot.Producers {
		reference := producer.Reference
		if hostaction.Digest(reference) != hostaction.Digest(in.Producers[ordinal]) {
			return deny()
		}
		guest, exists := guests[reference.HostID]
		if !exists || guest.HostIdentityDigest != producer.HostIdentityDigest {
			return deny()
		}
		var nonce [32]byte
		if _, err = rand.Read(nonce[:]); err != nil {
			return zero, nil, failure.New(generated.ErrorCodeIntegrityFailure, "native-nonce", false)
		}
		binding := generated.NativeObservationBinding{Schema: generated.SchemaIDNativeObservationBinding, SchemaVersion: "1.0.0", ScopeDigest: in.ScopeDigest, GuestID: guest.GuestID, ScenarioID: reference.ScenarioID, Ordinal: int64(ordinal), ControllerInstanceID: scope.ControllerInstanceID, RecoveryEpoch: in.RecoveryEpoch, PlanID: reference.PlanID, PlanDigest: reference.PlanDigest, RunID: reference.RunID, StepID: reference.StepID, LeaseID: reference.LeaseID, Nonce: "sha256:" + hex.EncodeToString(nonce[:]), Deadline: time.Now().UTC().Add(30 * time.Second).Truncate(time.Second).Format(time.RFC3339)}
		// The concrete observer performs fresh channel I/O here, after the repository
		// read has ended. No SQL transaction is held across external observation.
		observation, observeErr := observer.Observe(ctx, binding)
		if observeErr != nil {
			return deny()
		}
		if hostaction.Digest(observation.Binding) != hostaction.Digest(binding) || observation.ExecutableDigest != scope.ExecutableDigest || observation.DiskDigest != guest.DiskDigest || observation.FirmwareDigest != guest.FirmwareDigest {
			return deny()
		}
		if reference.ScenarioID == "action-replay" || reference.ScenarioID == "action-concurrency" {
			if s.adapters == nil || executions[ordinal].Result == nil {
				return deny()
			}
			implementation, resolveErr := s.adapters.Resolve("host-action")
			actual, ok := implementation.(*transport.Adapter)
			if resolveErr != nil || !ok {
				return deny()
			}
			witness, witnessErr := actual.NativeProtocolObservationForExecution(executions[ordinal].Result.BundleDigest, reference.RunID, reference.StepID, reference.LeaseID)
			if witnessErr != nil {
				return deny()
			}
			observation.ActionProtocol = &witness
		}
		observations = append(observations, observation)
	}
	if err = qualification.ValidateStageEvidence(in.Stage, executions, observations); err != nil {
		return deny()
	}
	observedAt := time.Now().UTC().Truncate(time.Second)
	sourceDigest := qualification.SourceDigest(scope)
	payload := generated.NativeQualification{Schema: generated.SchemaIDNativeQualification, SchemaVersion: "1.0.0", ControllerIdentity: controller, Stage: in.Stage, ScopeDigest: in.ScopeDigest, ProfileID: scope.ProfileID, ProfileLockDigest: scope.ProfileLockDigest, SourceCommit: scope.SourceCommit, SourceDigest: sourceDigest, ExecutableDigest: scope.ExecutableDigest, ControllerInstanceID: snapshot.ControllerInstanceID, RecoveryEpoch: in.RecoveryEpoch, ObservedAt: observedAt.Format(time.RFC3339), ExpiresAt: observedAt.Add(24 * time.Hour).Format(time.RFC3339), ObserverDigest: hostaction.Digest(observations), Producers: snapshot.Producers}
	bundle := generated.GateEvidenceBundle{Schema: generated.SchemaIDGateEvidenceBundle, SchemaVersion: "1.1.0", CollectorID: "native-debian-228", ObservedAt: payload.ObservedAt, NativeQualification: &payload, Attachments: []generated.GateEvidenceAttachment{}, Facts: []generated.GateEvidenceFact{{Schema: generated.SchemaIDGateEvidenceFact, SchemaVersion: "1.1.0", FactID: "native.profile-lock", ValueDigest: scope.ProfileLockDigest}, {Schema: generated.SchemaIDGateEvidenceFact, SchemaVersion: "1.1.0", FactID: "native.source", ValueDigest: sourceDigest}}, Checks: []generated.GateEvidenceCheck{{Schema: generated.SchemaIDGateEvidenceCheck, SchemaVersion: "1.1.0", CheckID: "native." + in.Stage, VerifierVersion: "1.0.0", Result: "passed", ResultDigest: sourceDigest}}}
	// The repository re-resolves the same production joins, current grants and
	// revision atomically; it alone fixes draft provenance to local/live.
	draft, err := gates.PutNativeGateDraft(ctx, store.NativeGateDraftRequest{Request: in, Payload: payload, Bundle: bundle, ResolvedDigest: snapshot.Digest, Attribution: a})
	if err != nil {
		return zero, nil, err
	}
	scenarios, err := qualification.SummarizeStageEvidence(in.Stage, executions, observations, scope.ProfileLockDigest, draft.BundleDigest)
	if err != nil {
		return zero, nil, err
	}
	return draft, scenarios, nil
}

// The launch remains pinned to its original controller and absolute window.
// Only a verified persisted restore transition can explain a new authority;
// producer resolution still rejects every prior-epoch baseline/role receipt.
func nativeCollectorAuthority(scope generated.QualificationScope, s store.NativeProducerSnapshot) bool {
	return store.NativeScopeAuthority(scope, s)
}
