//go:build !linux

package cijobguard

import (
	"context"
	"os"
)

type Cgroup struct{}

func OpenCgroup(*os.File) (*Cgroup, error) { return nil, ErrCgroup }
func (*Cgroup) Kill(context.Context) error { return ErrCgroup }
func (*Cgroup) Close() error               { return ErrCgroup }
