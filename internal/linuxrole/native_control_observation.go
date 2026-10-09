package linuxrole

import "github.com/vegastack/vegastack-labs/internal/generated"

// NativeControlHandoffObservation is read from the existing protected handoff
// receipt and independently refreshed process, writer-lock and API state. It is
// not a public request or a substitute for the approved handoff result.
type NativeControlHandoffObservation struct {
	Bundle        generated.HostActionBundle `json:"bundle"`
	Input         generated.LinuxRoleInput   `json:"input"`
	ReceiptDigest string                     `json:"receiptDigest"`
	RecordedState ControlServiceState        `json:"recordedState"`
	CurrentState  ControlServiceState        `json:"currentState"`
	ObservedAt    string                     `json:"observedAt"`
}
