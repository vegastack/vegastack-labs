package serverconfig

import (
	"encoding/json"
	"net/url"
	"regexp"
	"strings"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

var serviceProviderID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)
var serviceRepositoryPart = regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*$`)

// FreezeServiceBindings validates protected composition targets and owns copies
// of nested provider configuration. It performs no network or credential read.
func FreezeServiceBindings(input []generated.ServiceProviderBinding) ([]generated.ServiceProviderBinding, error) {
	invalid := func() ([]generated.ServiceProviderBinding, error) {
		return nil, failure.New(generated.ErrorCodeInputInvalid, "service-bindings", false)
	}
	if len(input) > 128 {
		return invalid()
	}
	out := make([]generated.ServiceProviderBinding, 0, len(input))
	bindings, services, resources := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, b := range input {
		raw, e := json.Marshal(b)
		if e != nil || generated.ValidateContractJSON(generated.SchemaIDServiceProviderBinding, raw, generated.ContractExact) != nil || b.Coolify == nil {
			return invalid()
		}
		c := *b.Coolify
		if !serviceOrigin(c.Origin, "/api/v1") || !serviceProviderID.MatchString(c.ProjectUUID) || !serviceProviderID.MatchString(c.Environment) || !serviceProviderID.MatchString(c.ApplicationUUID) || (c.DestinationType != "App\\Models\\StandaloneDocker" && c.DestinationType != "App\\Models\\SwarmDocker") {
			return invalid()
		}
		key := c.Origin + "\x00" + c.ApplicationUUID
		if bindings[b.BindingID] || services[b.ServiceID] || resources[key] {
			return invalid()
		}
		bindings[b.BindingID], services[b.ServiceID], resources[key] = true, true, true
		b.Coolify = &c
		if b.Harbor != nil {
			h := *b.Harbor
			if !serviceOrigin(h.Origin, "") || !serviceRepositoryPart.MatchString(h.Project) || strings.ContainsAny(h.RobotUsername, ":\r\n\x00") || strings.TrimSpace(h.RobotUsername) != h.RobotUsername {
				return invalid()
			}
			for _, part := range strings.Split(h.Repository, "/") {
				if !serviceRepositoryPart.MatchString(part) {
					return invalid()
				}
			}
			b.Harbor = &h
		}
		out = append(out, b)
	}
	return out, nil
}

func serviceOrigin(raw, path string) bool {
	u, e := url.Parse(raw)
	return e == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.Opaque == "" && u.RawPath == "" && u.Path == path && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && strings.ToLower(u.Host) == u.Host && !strings.ContainsAny(raw, " \\\t\r\n")
}
