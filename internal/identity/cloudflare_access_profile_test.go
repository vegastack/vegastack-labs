package identity

import (
	"strings"
	"testing"
	"time"
)

const validCloudflareProfile = `{"schema":"vegastack-labs.dev/cloudflare-access-profile","schemaVersion":"1.0.0","issuer":"https://team.cloudflareaccess.com","audience":"audience-id","certificatesUrl":"https://team.cloudflareaccess.com/cdn-cgi/access/certs","clockSkewSeconds":30,"maxTokenBytes":16384,"knownKeyOutageSeconds":3600}`

func TestDecodeCloudflareAccessProfileIsStrictBoundedAndProviderSpecific(t *testing.T) {
	config, err := decodeCloudflareAccessProfile(strings.NewReader(validCloudflareProfile))
	if err != nil {
		t.Fatal(err)
	}
	if config.Issuer != "https://team.cloudflareaccess.com" || config.ClockSkew != 30*time.Second || config.KnownKeyOutageLimit != time.Hour {
		t.Fatalf("config = %#v", config)
	}

	for name, body := range map[string]string{
		"unknown":   strings.Replace(validCloudflareProfile, `"issuer":`, `"unknown":true,"issuer":`, 1),
		"multiple":  validCloudflareProfile + validCloudflareProfile,
		"oversized": validCloudflareProfile + strings.Repeat(" ", maxCloudflareAccessProfileBytes),
		"http":      strings.Replace(validCloudflareProfile, "https://team.cloudflareaccess.com", "http://team.cloudflareaccess.com", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeCloudflareAccessProfile(strings.NewReader(body)); err == nil {
				t.Fatal("invalid adapter profile accepted")
			}
		})
	}
}
