package server

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"runtime"
	"time"

	"github.com/vegastack/vegastack-labs/internal/gate"
	"github.com/vegastack/vegastack-labs/internal/result"
	"github.com/vegastack/vegastack-labs/internal/store"
)

func nativeGateRepository(authority *store.Store, build result.BuildInfo) *store.GateRepository {
	// Missing native build pins leave qualification unavailable without disabling
	// ordinary local operation. Measure the running ELF, not its replaceable path.
	plain := func() *store.GateRepository { return store.NewGateRepository(authority) }
	if runtime.GOOS != "linux" || build.SourceRevision == nil {
		return plain()
	}
	f, err := os.Open("/proc/self/exe")
	if err != nil {
		return plain()
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() <= 0 || st.Size() > 256<<20 {
		return plain()
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, (256<<20)+1))
	if err != nil || n != st.Size() {
		return plain()
	}
	v, err := gate.NewNativeHostProvenance(*build.SourceRevision, "sha256:"+hex.EncodeToString(h.Sum(nil)), time.Now)
	if err != nil {
		return plain()
	}
	return store.NewGateRepositoryWithHostProvenance(authority, v)
}
