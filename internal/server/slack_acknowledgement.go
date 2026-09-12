package server

import (
	"github.com/vegastack/vegastack-labs/internal/adapters/slack"
	"github.com/vegastack/vegastack-labs/internal/api"
)

// These compile-time seams keep the optional Slack adapter inside the existing
// server lifecycle and local API composition. Deployment profile and protected
// credential resolution are intentionally separate operator-controlled inputs.
var (
	_ BackgroundService            = (*slack.Adapter)(nil)
	_ api.AcknowledgementPublisher = (*slack.Adapter)(nil)
)
