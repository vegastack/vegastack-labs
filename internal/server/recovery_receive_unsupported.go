//go:build !linux

package server

import (
	"context"
	"fmt"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"io"
)

const RecoveryReceiveMode = "server-recovery-receive-once"

func RecoveryReceiveDispatcher(string) hostaction.Dispatcher {
	return hostaction.ProductionDispatcher()
}
func RunRecoveryReceiveOnce(context.Context, string, io.Writer) error {
	return fmt.Errorf("recovery receive unavailable")
}
