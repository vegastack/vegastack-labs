package hostaction

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

const RecoveryReceiveAction = "debian.control.recovery-receive"
const MaximumRecoveryCandidateBytes int64 = 512 << 20
const MaximumRecoveryJournalBytes int64 = 32768

// RecoveryPayloadHandler is selected only for the closed recovery-receive
// action, after signed authorization and its durable one-use execution claim.
// Implementations must validate exact signed lengths/digests and trailing EOF
// before promoting anything. Execute remains unavailable for this action.
type RecoveryPayloadHandler interface {
	Handler
	ExecuteRecoveryPayload(context.Context, generated.HostActionBundle, io.Reader) (generated.HostActionResult, error)
}

// CopyRecoveryPayload consumes exactly one signed segment without reading the
// next segment. The caller checks EOF after the journal, before promotion. No
// plaintext buffers are retained beyond the bounded copy buffer.
func CopyRecoveryPayload(ctx context.Context, dst io.Writer, src io.Reader, length, maximum int64, digest string) error {
	if ctx == nil || ctx.Err() != nil || dst == nil || src == nil || length <= 0 || maximum <= 0 || maximum > MaximumRecoveryCandidateBytes || length > maximum || len(digest) != 71 || digest[:7] != "sha256:" {
		return blocked()
	}
	decoded, err := hex.DecodeString(digest[7:])
	if err != nil || len(decoded) != sha256.Size {
		return blocked()
	}
	hash := sha256.New()
	remaining := length
	buffer := make([]byte, 32768)
	defer func() {
		for i := range buffer {
			buffer[i] = 0
		}
	}()
	for remaining > 0 {
		if ctx.Err() != nil {
			return blocked()
		}
		n := int64(len(buffer))
		if remaining < n {
			n = remaining
		}
		got, readErr := io.ReadFull(src, buffer[:n])
		if readErr != nil || int64(got) != n {
			return blocked()
		}
		if ctx.Err() != nil {
			return blocked()
		}
		written, writeErr := dst.Write(buffer[:got])
		if writeErr != nil || written != got {
			return blocked()
		}
		_, _ = hash.Write(buffer[:got])
		remaining -= int64(got)
	}
	if ctx.Err() != nil || "sha256:"+hex.EncodeToString(hash.Sum(nil)) != digest {
		return blocked()
	}
	return nil
}
