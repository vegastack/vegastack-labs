// Package serverconfig loads and validates protected local control-service profiles.
package serverconfig

import (
	"context"
	"encoding/json"
	"io"
	"io/fs"
	"net/netip"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
)

const maxProfileBytes = 64 * 1024

type Profile struct {
	SocketPath                     string
	InventoryExportRoot            string
	SocketOwnerUID                 uint32
	SocketGroupGID                 *uint32
	SocketMode                     fs.FileMode
	ShutdownGrace                  time.Duration
	PrincipalBindings              []identity.Binding
	RemoteRead                     RemoteRead
	SlackAcknowledgementConfigPath string
}

type RemoteRead struct {
	Enabled            bool
	ConfigurationValid bool
	BindAddress        string
	PublicOrigin       string
	ExactHost          string
	TLSCertificatePath string
	TLSPrivateKeyPath  string
	IdentityAdapter    string
	IdentityConfigPath string
}

type Loader interface {
	Load(context.Context, string) (Profile, error)
}

func decodeGeneratedProfile(reader io.Reader) (generated.ServerProfile, error) {
	content, err := io.ReadAll(io.LimitReader(reader, maxProfileBytes+1))
	if err != nil || len(content) == 0 || len(content) > maxProfileBytes {
		return generated.ServerProfile{}, failure.New("INPUT_INVALID", "server-config", false)
	}
	decoder := json.NewDecoder(strings.NewReader(string(content)))
	decoder.DisallowUnknownFields()
	var profile generated.ServerProfile
	if err := decoder.Decode(&profile); err != nil {
		return generated.ServerProfile{}, failure.New("INPUT_INVALID", "server-config", false)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return generated.ServerProfile{}, failure.New("INPUT_INVALID", "server-config", false)
	}
	return profile, nil
}

func convertGeneratedProfile(input generated.ServerProfile, expectedOwnerUID uint32) (Profile, error) {
	invalid := func() (Profile, error) {
		return Profile{}, failure.New("INPUT_INVALID", "server-config", false)
	}
	if input.Schema != generated.SchemaIDServerProfile || input.SchemaVersion != "1.1.0" ||
		input.SocketOwnerUID < 0 || input.SocketOwnerUID > int64(^uint32(0)) || uint32(input.SocketOwnerUID) != expectedOwnerUID ||
		input.ShutdownGraceSeconds != 5 || len(input.SocketPath) > 107 || strings.ContainsRune(input.SocketPath, 0) ||
		!filepath.IsAbs(input.SocketPath) || filepath.Clean(input.SocketPath) != input.SocketPath ||
		len(input.InventoryExportRoot) < 2 || len(input.InventoryExportRoot) > 4096 || strings.ContainsRune(input.InventoryExportRoot, 0) ||
		!filepath.IsAbs(input.InventoryExportRoot) || filepath.Clean(input.InventoryExportRoot) != input.InventoryExportRoot || input.InventoryExportRoot == string(filepath.Separator) {
		return invalid()
	}

	var mode fs.FileMode
	var group *uint32
	switch input.SocketMode {
	case "0600":
		if input.SocketGroupGID != nil {
			return invalid()
		}
		mode = 0o600
	case "0660":
		if input.SocketGroupGID == nil || *input.SocketGroupGID < 0 || *input.SocketGroupGID > int64(^uint32(0)) {
			return invalid()
		}
		value := uint32(*input.SocketGroupGID)
		group = &value
		mode = 0o660
	default:
		return invalid()
	}

	if len(input.PrincipalBindings) == 0 || len(input.PrincipalBindings) > 256 {
		return invalid()
	}
	bindings := make([]identity.Binding, len(input.PrincipalBindings))
	for index, binding := range input.PrincipalBindings {
		if binding.UID < 0 || binding.UID > int64(^uint32(0)) {
			return invalid()
		}
		bindings[index] = identity.Binding{UID: uint32(binding.UID), PrincipalID: binding.PrincipalID}
	}
	if _, err := identity.NewLocalPrincipalResolver(bindings); err != nil {
		return invalid()
	}
	remoteRead, err := convertRemoteRead(input.RemoteRead)
	if err != nil {
		// Remote browser configuration is optional. Preserve strict validation,
		// but carry its failure to the independently supervised remote listener
		// instead of preventing the protected local Unix service from starting.
		remoteRead = RemoteRead{Enabled: true}
	}
	slackConfigPath := input.SlackAcknowledgementConfigPath
	if slackConfigPath != "" && (len(slackConfigPath) > 4096 || !filepath.IsAbs(slackConfigPath) || filepath.Clean(slackConfigPath) != slackConfigPath || slackConfigPath == string(filepath.Separator)) {
		return invalid()
	}
	return Profile{
		SocketPath:                     input.SocketPath,
		InventoryExportRoot:            input.InventoryExportRoot,
		SocketOwnerUID:                 expectedOwnerUID,
		SocketGroupGID:                 group,
		SocketMode:                     mode,
		ShutdownGrace:                  5 * time.Second,
		PrincipalBindings:              append([]identity.Binding(nil), bindings...),
		RemoteRead:                     remoteRead,
		SlackAcknowledgementConfigPath: slackConfigPath,
	}, nil
}

func convertRemoteRead(input generated.RemoteReadProfile) (RemoteRead, error) {
	invalid := func() (RemoteRead, error) {
		return RemoteRead{}, failure.New("INPUT_INVALID", "server-config", false)
	}
	pointers := []*string{input.BindAddress, input.PublicOrigin, input.TLSCertificatePath, input.TLSPrivateKeyPath, input.IdentityAdapter, input.IdentityConfigPath}
	if !input.Enabled {
		for _, value := range pointers {
			if value != nil {
				return invalid()
			}
		}
		return RemoteRead{ConfigurationValid: true}, nil
	}
	for _, value := range pointers {
		if value == nil || *value == "" || strings.TrimSpace(*value) != *value || strings.ContainsRune(*value, 0) {
			return invalid()
		}
	}
	address, err := netip.ParseAddrPort(*input.BindAddress)
	if err != nil || address.Port() == 0 || address.Addr().IsUnspecified() || address.Addr().IsMulticast() {
		return invalid()
	}
	origin, err := url.Parse(*input.PublicOrigin)
	if err != nil || origin.Scheme != "https" || origin.Host == "" || origin.Hostname() == "" || origin.User != nil || origin.Path != "" || origin.RawPath != "" || origin.RawQuery != "" || origin.Fragment != "" || origin.ForceQuery || origin.Host != strings.ToLower(origin.Host) || origin.String() != *input.PublicOrigin {
		return invalid()
	}
	for _, candidate := range []string{*input.TLSCertificatePath, *input.TLSPrivateKeyPath, *input.IdentityConfigPath} {
		if len(candidate) > 4096 || !filepath.IsAbs(candidate) || filepath.Clean(candidate) != candidate || candidate == string(filepath.Separator) {
			return invalid()
		}
	}
	if *input.IdentityAdapter != "cloudflare-access" {
		return invalid()
	}
	return RemoteRead{
		Enabled:            true,
		ConfigurationValid: true,
		BindAddress:        address.String(),
		PublicOrigin:       origin.String(),
		ExactHost:          origin.Host,
		TLSCertificatePath: *input.TLSCertificatePath,
		TLSPrivateKeyPath:  *input.TLSPrivateKeyPath,
		IdentityAdapter:    *input.IdentityAdapter,
		IdentityConfigPath: *input.IdentityConfigPath,
	}, nil
}
