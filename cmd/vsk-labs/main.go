package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"os/signal"
	"syscall"

	"github.com/vegastack/vegastack-labs/internal/cli"
	"github.com/vegastack/vegastack-labs/internal/release"
)

var (
	toolVersion    = "0.0.0-dev"
	releaseBuildID = "development"
	sourceRevision = ""
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var revision *string
	if sourceRevision != "" {
		value := sourceRevision
		revision = &value
	}
	app := cli.New(os.Stdout, os.Stderr, cli.BuildInfo{
		ToolVersion:    toolVersion,
		ReleaseBuildID: releaseBuildID,
		SourceRevision: revision,
	}, newRequestID, cli.WithReleaseOperations(release.NewService(release.SigstoreBundleVerifier{})))
	os.Exit(app.Run(ctx, os.Args[1:]))
}

func newRequestID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return "request-" + hex.EncodeToString(value[:]), nil
}
