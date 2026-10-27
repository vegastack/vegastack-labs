//go:build linux

package cijobrunner

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

func TestPrivateWorkerRejectsMissingAuthorizedBootstrap(t *testing.T) {
	if RunWorker(context.Background(), io.NopCloser(strings.NewReader("{}\n")), io.Discard) == nil {
		t.Fatal("worker accepted no protected root bootstrap")
	}
}
func TestNativeConfigurationCannotChooseAnotherPath(t *testing.T) {
	if _, e := LoadNativeConfig(t.TempDir() + "/config.json"); e == nil {
		t.Fatal("arbitrary protected config path accepted")
	}
}
func TestCIHandlerRejectsUnsignedOrdinaryExecution(t *testing.T) {
	h := &CIHandler{}
	if _, e := h.Execute(context.Background(), generated.HostActionBundle{}); e == nil {
		t.Fatal("nonduplex launch")
	}
}
