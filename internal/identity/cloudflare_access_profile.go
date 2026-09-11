package identity

import (
	"context"
	"encoding/json"
	"io"
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

const maxCloudflareAccessProfileBytes = 64 * 1024

func LoadCloudflareAccessProfile(ctx context.Context, profilePath string) (CloudflareAccessConfig, error) {
	if err := ctx.Err(); err != nil {
		return CloudflareAccessConfig{}, failure.New("INTERRUPTED", "cloudflare-access-config", false)
	}
	reader, err := openProtectedCloudflareAccessProfile(profilePath)
	if err != nil {
		return CloudflareAccessConfig{}, err
	}
	defer reader.Close()
	config, err := decodeCloudflareAccessProfile(reader)
	if err != nil {
		return CloudflareAccessConfig{}, err
	}
	if err := ctx.Err(); err != nil {
		return CloudflareAccessConfig{}, failure.New("INTERRUPTED", "cloudflare-access-config", false)
	}
	return config, nil
}

func decodeCloudflareAccessProfile(reader io.Reader) (CloudflareAccessConfig, error) {
	content, err := io.ReadAll(io.LimitReader(reader, maxCloudflareAccessProfileBytes+1))
	if err != nil || len(content) == 0 || len(content) > maxCloudflareAccessProfileBytes {
		return CloudflareAccessConfig{}, failure.New("INPUT_INVALID", "cloudflare-access-config", false)
	}
	decoder := json.NewDecoder(strings.NewReader(string(content)))
	decoder.DisallowUnknownFields()
	var profile generated.CloudflareAccessProfile
	if err := decoder.Decode(&profile); err != nil {
		return CloudflareAccessConfig{}, failure.New("INPUT_INVALID", "cloudflare-access-config", false)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return CloudflareAccessConfig{}, failure.New("INPUT_INVALID", "cloudflare-access-config", false)
	}
	if profile.Schema != generated.SchemaIDCloudflareAccessProfile || profile.SchemaVersion != "1.0.0" ||
		profile.ClockSkewSeconds < 0 || profile.ClockSkewSeconds > 300 || profile.MaxTokenBytes < 1024 || profile.MaxTokenBytes > 64*1024 ||
		profile.KnownKeyOutageSeconds <= 0 || profile.KnownKeyOutageSeconds > 24*60*60 {
		return CloudflareAccessConfig{}, failure.New("INPUT_INVALID", "cloudflare-access-config", false)
	}
	config := CloudflareAccessConfig{
		Issuer:              profile.Issuer,
		Audience:            profile.Audience,
		CertificatesURL:     profile.CertificatesURL,
		ClockSkew:           time.Duration(profile.ClockSkewSeconds) * time.Second,
		MaxTokenBytes:       int(profile.MaxTokenBytes),
		KnownKeyOutageLimit: time.Duration(profile.KnownKeyOutageSeconds) * time.Second,
	}
	validated, err := validateCloudflareAccessConfig(config)
	if err != nil {
		return CloudflareAccessConfig{}, failure.New("INPUT_INVALID", "cloudflare-access-config", false)
	}
	return validated, nil
}
