package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"os/signal"
	"syscall"

	"github.com/vegastack/vegastack-labs/internal/backup"
	"github.com/vegastack/vegastack-labs/internal/cli"
	"github.com/vegastack/vegastack-labs/internal/clientfile"
	"github.com/vegastack/vegastack-labs/internal/release"
	"github.com/vegastack/vegastack-labs/internal/result"
	"github.com/vegastack/vegastack-labs/internal/server"
)

var (
	toolVersion    = "0.0.0-dev"
	releaseBuildID = "development"
	sourceRevision = ""
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == backup.CustodyPolicyCheckMode {
		os.Exit(backup.RunCustodyPolicyCheck(context.Background(), os.Stdin))
	}
	if len(os.Args) == 3 && os.Args[1] == backup.CustodySystemdMode {
		if backup.RunCustodySupervisor(os.Args[2]) != nil {
			os.Exit(1)
		}
		return
	}
	if os.Getenv("VSK_BACKUP_CUSTODY") == "1" {
		if len(os.Args) != 4 || os.Args[1] != "backup-custody" || os.Args[2] != "--policy" || backup.RunCustodyChild(os.Args[3]) != nil {
			os.Exit(1)
		}
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if handled, code := runPrivateNativeProbe(ctx, os.Args[1:]); handled {
		os.Exit(code)
	}

	var revision *string
	if sourceRevision != "" {
		value := sourceRevision
		revision = &value
	}
	build := result.BuildInfo{
		ToolVersion:    toolVersion,
		ReleaseBuildID: releaseBuildID,
		SourceRevision: revision,
	}
	recoveryCanaryCapabilities := server.NewSystemRecoveryCanaryCapabilities()
	recoveryCanaryPorts, err := server.NewQualifiedRecoveryCanaryPortFactory(recoveryCanaryCapabilities)
	if err != nil {
		os.Exit(1)
	}
	offsiteRunners := server.NewProfileOffsiteRunnerSource(server.NewLabsR2Runner)
	operations := server.NewOperations(build, newRequestID,
		server.WithOffsiteEffectFactory(server.NewProductionOffsiteEffectFactory(offsiteRunners)),
		server.WithRecoveryCanaryPortFactory(recoveryCanaryPorts))
	app := cli.New(os.Stdout, os.Stderr, build, newRequestID,
		cli.WithInput(os.Stdin),
		cli.WithReleaseOperations(release.NewService(release.SigstoreBundleVerifier{})),
		cli.WithServerOperations(operations),
		cli.WithControlOperations(operations, clientfile.NewReader()),
		cli.WithCredentialControlOperations(operations),
	)
	os.Exit(app.Run(ctx, os.Args[1:]))
}

func newRequestID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return "request-" + hex.EncodeToString(value[:]), nil
}
