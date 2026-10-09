//go:build linux

package hostaction

import (
	"context"
	"os"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

// InspectNativeExecution reads only the fixed installed action boundary. No
// directory, claim, result or lock is created by this observation.
func InspectNativeExecution(ctx context.Context, bundle generated.HostActionBundle) (NativeExecutionObservation, error) {
	if ctx == nil || ctx.Err() != nil || os.Geteuid() != 0 {
		return NativeExecutionObservation{}, blocked()
	}
	policy, err := LoadPolicy("/etc/vsk-labs/host-action.json")
	if err != nil || policy.ReceiptDirectory != "/var/lib/vsk-labs/host-action" || bundle.HostID != policy.HostID || bundle.HostIdentityDigest != policy.HostIdentityDigest || bundle.CallerUID != int64(policy.CallerUID) {
		return NativeExecutionObservation{}, blocked()
	}
	receipts, err := OpenReceipts(policy.ReceiptDirectory, 0)
	if err != nil {
		return NativeExecutionObservation{}, err
	}
	defer receipts.Close()
	return receipts.inspectExecution(bundle)
}
