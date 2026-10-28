package cloudflare

import _ "embed"

//go:embed assets/site-watchdog.mjs
var siteWatchdogSource []byte

// SiteWatchdogArtifact is inert adapter source, not a deployment or gate proof.
// The typed deployment owner must require current G-011 evidence and an exact
// acknowledged plan before provisioning its bucket/binding, secrets or schedule.
type SiteWatchdogArtifact struct {
	Source           []byte
	Cron             string
	HeartbeatKey     string
	DeliveryStateKey string
	StaleSeconds     int
}

func SiteWatchdog() SiteWatchdogArtifact {
	return SiteWatchdogArtifact{Source: append([]byte(nil), siteWatchdogSource...), Cron: "*/5 * * * *", HeartbeatKey: "heartbeat.json", DeliveryStateKey: "watchdog-state.json", StaleSeconds: 900}
}
