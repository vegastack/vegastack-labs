package server

import (
	"context"
	"strconv"
	"strings"

	"github.com/vegastack/vegastack-labs/internal/failure"
)

type Platform struct {
	OS           string
	Architecture string
	Distribution string
	Major        int
}

type PlatformProbe interface {
	Current(context.Context) (Platform, error)
}

func parseOSRelease(content []byte, operatingSystem, architecture string) (Platform, error) {
	values := make(map[string]string)
	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || key == "" {
			return Platform{}, failure.New("UNSUPPORTED_PLATFORM", "server-platform", false)
		}
		if strings.HasPrefix(value, `"`) {
			unquoted, err := strconv.Unquote(value)
			if err != nil {
				return Platform{}, failure.New("UNSUPPORTED_PLATFORM", "server-platform", false)
			}
			value = unquoted
		}
		if key == "ID" || key == "VERSION_ID" {
			if _, duplicate := values[key]; duplicate {
				return Platform{}, failure.New("UNSUPPORTED_PLATFORM", "server-platform", false)
			}
			values[key] = value
		}
	}
	major, err := strconv.Atoi(values["VERSION_ID"])
	if err != nil || operatingSystem != "linux" || architecture != "amd64" || values["ID"] != "debian" || major != 13 {
		return Platform{}, failure.New("UNSUPPORTED_PLATFORM", "server-platform", false)
	}
	return Platform{OS: operatingSystem, Architecture: architecture, Distribution: values["ID"], Major: major}, nil
}

func supportedPlatform(platform Platform) bool {
	return platform.OS == "linux" && platform.Architecture == "amd64" && platform.Distribution == "debian" && platform.Major == 13
}
