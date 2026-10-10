//go:build linux || darwin

package hostaction

import (
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"golang.org/x/sys/unix"
	"io"
	"os"
)

func (r *Receipts) inspectExecution(bundle generated.HostActionBundle) (NativeExecutionObservation, error) {
	var out NativeExecutionObservation
	digest, err := BundleDigest(bundle)
	if err != nil || r == nil {
		return out, blocked()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.dir == nil {
		return out, blocked()
	}
	key := ExecutionDigest(bundle)
	read := func(suffix string, limit int64) ([]byte, error) {
		fd, e := unix.Openat(int(r.dir.Fd()), key[7:]+suffix, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if e != nil {
			return nil, blocked()
		}
		f := os.NewFile(uintptr(fd), "native-execution-observation")
		defer f.Close()
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || st.Uid != r.uid || st.Nlink != 1 || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0777 != 0600 || st.Size < 1 || st.Size > limit {
			return nil, blocked()
		}
		raw, e := io.ReadAll(io.LimitReader(f, limit+1))
		if e != nil || int64(len(raw)) > limit {
			return nil, blocked()
		}
		return raw, nil
	}
	claim, err := read(".json", MaximumFrame)
	if err != nil {
		return out, err
	}
	var c struct {
		BundleDigest string `json:"bundleDigest"`
		Status       string `json:"status"`
	}
	if json.Unmarshal(claim, &c) != nil || c.BundleDigest != digest || c.Status != "claimed" {
		return out, blocked()
	}
	// Require the exact production claim representation; duplicate or extra keys
	// cannot hide behind ordinary JSON decoding.
	canonical, _ := json.Marshal(c)
	if string(claim) != string(canonical) {
		return out, blocked()
	}
	raw, err := read(".result.json", MaximumResultFrame)
	if err != nil {
		return out, err
	}
	var result generated.HostActionResult
	if generated.ValidateContractJSON(generated.SchemaIDHostActionResult, raw, generated.ContractExact) != nil || json.Unmarshal(raw, &result) != nil || ValidateResult(result) != nil || result.BundleDigest != digest {
		return out, blocked()
	}
	return NativeExecutionObservation{ExecutionDigest: key, BundleDigest: digest, ClaimDigest: BytesDigest(claim), ResultDigest: BytesDigest(raw), Status: result.Status}, nil
}
