//go:build !linux

package cijobrunner

import (
	"context"
	"io"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

type Receipt struct {
	Stage, ContainerID, LogDigest string
	Stopped, VolumesRemoved       bool
}
type DockerConfig struct{ ExecutablePath, SocketPath, VSKPath string }
type Docker struct{}

func NewDocker(DockerConfig, RuntimeProfile, NetworkVerifier) (*Docker, error) {
	return nil, ErrBlocked
}
func (*Docker) Run(context.Context, Spec, Session) (Receipt, error) { return Receipt{}, ErrBlocked }

type SpecSource interface {
	Load(context.Context, generated.HostActionBundle) (Spec, RuntimeProfile, error)
}
type CIHandler struct{}

func NewCIHandler(SpecSource, *Docker) (*CIHandler, error) { return nil, ErrBlocked }
func (*CIHandler) Execute(context.Context, generated.HostActionBundle) (generated.HostActionResult, error) {
	return generated.HostActionResult{}, ErrBlocked
}
func (*CIHandler) ExecuteCI(context.Context, generated.HostActionBundle, io.ReadCloser, io.Writer) (generated.HostActionResult, error) {
	return generated.HostActionResult{}, ErrBlocked
}
func (*CIHandler) Verify(context.Context, generated.HostActionBundle, generated.HostActionResult) error {
	return ErrBlocked
}
