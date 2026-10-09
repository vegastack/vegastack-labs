package store

import (
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

// NativeProducerSnapshot is resolved internally from existing production run,
// receipt and control-result rows. No API accepts this type as evidence.
type NativeProducerSnapshot struct {
	Revision               RevisionToken
	ControllerInstanceID   string
	VerifiedRestoreBinding *generated.RestoreBinding
	Producers              []generated.NativeQualificationProducer
	Measurements           []HostAdmissionMeasurement
	Executions             []NativeProducerExecution
	// Digest binds the exact independently resolved snapshot for revalidation
	// after observer I/O and before the inert draft is written.
	Digest string
}

// NativeGateDraftRequest is an in-process collector write. The repository
// independently resolves Request again and fixes provenance to local/live.
// Payload and Bundle.NativeQualification must be identical; neither assigns
// authority merely by being populated.
type NativeGateDraftRequest struct {
	Request        generated.NativeCollectRequest
	Payload        generated.NativeQualification
	Bundle         generated.GateEvidenceBundle
	ResolvedDigest string
	Attribution    audit.Attribution
}

// HostNativeProducerBinding is the durable applied native lineage resolved for
// the admission verifier. These fields are not reconstructed from public report
// JSON: the store first verifies internal origin and all production joins.
type HostNativeProducerBinding struct {
	CurrentControllerInstanceID string
	Qualification               generated.NativeQualification
	Applied                     HostAppliedBinding
	Producers                   []generated.NativeQualificationProducer
	Measurements                []HostAdmissionMeasurement
	Executions                  []NativeProducerExecution
}

// NativeProducerExecution retains the actual terminal receipt and optional
// canonical action result, including expected denials. Scenario validators must
// derive their expectations from the fixed catalog rather than caller flags.
type NativeProducerExecution struct {
	Credential            *NativeCredentialEvidence
	Reference             generated.NativeProducerReference
	Plan                  generated.Plan
	Receipt               generated.ExecutionReceipt
	Result                *generated.HostActionResult
	ReplacementRecovery   *NativeReplacementRecoveryEvidence
	ControlSetupAuthority *NativeControlSetupAuthority
}
