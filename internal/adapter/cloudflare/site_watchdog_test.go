package cloudflare

import (
	"bytes"
	"testing"
)

func TestSiteWatchdogArtifactIsVersionedAndIndependentCopy(t *testing.T) {
	artifact := SiteWatchdog()
	if artifact.Cron != "*/5 * * * *" || artifact.StaleSeconds != 900 || artifact.HeartbeatKey == artifact.DeliveryStateKey || !bytes.Contains(artifact.Source, []byte("export async function checkSite")) {
		t.Fatal("missing watchdog contract")
	}
	artifact.Source[0] = '!'
	if SiteWatchdog().Source[0] == '!' {
		t.Fatal("caller mutated embedded adapter source")
	}
}
