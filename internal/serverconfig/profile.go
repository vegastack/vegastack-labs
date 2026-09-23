// Package serverconfig loads and validates protected local control-service profiles.
package serverconfig

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/fs"
	"net/netip"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/backupidentity"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/principal"
)

const maxProfileBytes = 64 * 1024

var offsiteProfileToken = regexp.MustCompile(`^[a-z][a-z0-9._:-]{0,127}$`)
var offsiteBucketName = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,62}$`)

type Profile struct {
	SocketPath                       string
	ConstrainedSSH                   *ConstrainedSSH
	InventoryExportRoot              string
	SocketOwnerUID                   uint32
	SocketGroupGID                   *uint32
	SocketMode                       fs.FileMode
	ShutdownGrace                    time.Duration
	PrincipalBindings                []principal.Binding
	RemoteRead                       RemoteRead
	AcknowledgementAdapterConfigPath string
	LocalBackup                      *LocalBackup
	OffsiteBackup                    *OffsiteBackup
}

// LocalBackup names the protected server-owned local recovery roots and the
// pinned restic executable. It is an all-or-none profile field: absent disables
// local backup creation entirely, and no declaration can override it. Callers
// select registered repository/source IDs, never these host paths.
type LocalBackup struct {
	StandardRoot         string
	CriticalRoot         string
	ResticBinaryPath     string
	CustodyPolicyPath    string
	SourceID             string
	StandardRepositoryID string
	CriticalRepositoryID string
}

// OffsiteBackup contains only non-secret destination identity and evidence
// bindings. It is complete-or-absent; parent credential material is resolved
// just in time through its logical reference.
type OffsiteBackup struct {
	Endpoint, Bucket, Prefix             string
	ParentReferenceID, ParentFingerprint string
	RuleDigest, G008EvidenceDigest       string
}

// ConstrainedSSH is a client-only transport. Arguments are produced by the
// typed client profile and never contain a remote command.
type ConstrainedSSH struct {
	Executable     string
	Arguments      []string
	SSHPrincipalID string
	DeviceID       string
	RecoveryEpoch  int64
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
	if input.Schema != generated.SchemaIDServerProfile || input.SchemaVersion != "1.3.0" ||
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
	bindings := make([]principal.Binding, len(input.PrincipalBindings))
	for index, binding := range input.PrincipalBindings {
		if binding.UID < 0 || binding.UID > int64(^uint32(0)) {
			return invalid()
		}
		bindings[index] = principal.Binding{UID: uint32(binding.UID), PrincipalID: binding.PrincipalID}
	}
	if _, err := principal.NewLocalPrincipalResolver(bindings); err != nil {
		return invalid()
	}
	remoteRead, err := convertRemoteRead(input.RemoteRead)
	if err != nil {
		// Remote browser configuration is optional. Preserve strict validation,
		// but carry its failure to the independently supervised remote listener
		// instead of preventing the protected local Unix service from starting.
		remoteRead = RemoteRead{Enabled: true}
	}
	adapterConfigPath := input.AcknowledgementAdapterConfigPath
	if adapterConfigPath != "" && (len(adapterConfigPath) > 4096 || !filepath.IsAbs(adapterConfigPath) || filepath.Clean(adapterConfigPath) != adapterConfigPath || adapterConfigPath == string(filepath.Separator)) {
		return invalid()
	}
	localBackup, err := convertLocalBackup(input)
	if err != nil {
		return invalid()
	}
	offsiteBackup, err := convertOffsiteBackup(input, localBackup)
	if err != nil {
		return invalid()
	}
	return Profile{
		SocketPath:                       input.SocketPath,
		InventoryExportRoot:              input.InventoryExportRoot,
		SocketOwnerUID:                   expectedOwnerUID,
		SocketGroupGID:                   group,
		SocketMode:                       mode,
		ShutdownGrace:                    5 * time.Second,
		PrincipalBindings:                append([]principal.Binding(nil), bindings...),
		RemoteRead:                       remoteRead,
		AcknowledgementAdapterConfigPath: adapterConfigPath,
		LocalBackup:                      localBackup,
		OffsiteBackup:                    offsiteBackup,
	}, nil
}

func convertOffsiteBackup(input generated.ServerProfile, local *LocalBackup) (*OffsiteBackup, error) {
	values := []*string{input.OffsiteEndpoint, input.OffsiteBucket, input.OffsitePrefix, input.OffsiteParentReferenceID,
		input.OffsiteParentFingerprint, input.OffsiteRuleDigest, input.OffsiteG008EvidenceDigest}
	present := 0
	for _, value := range values {
		if value != nil {
			present++
		}
	}
	if present == 0 {
		return nil, nil
	}
	if present != len(values) || local == nil {
		return nil, failure.New("INPUT_INVALID", "server-config", false)
	}
	endpoint, err := url.Parse(*input.OffsiteEndpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" ||
		endpoint.Path != "" || endpoint.Host != endpoint.Hostname() || !strings.HasSuffix(strings.ToLower(endpoint.Hostname()), ".r2.cloudflarestorage.com") ||
		!offsiteBucketName.MatchString(*input.OffsiteBucket) || !offsiteProfileToken.MatchString(*input.OffsiteParentReferenceID) ||
		*input.OffsitePrefix == "" || strings.HasPrefix(*input.OffsitePrefix, "/") || strings.Contains(*input.OffsitePrefix, "..") || filepath.Clean(*input.OffsitePrefix) != *input.OffsitePrefix {
		return nil, failure.New("INPUT_INVALID", "server-config", false)
	}
	for _, digest := range []string{*input.OffsiteParentFingerprint, *input.OffsiteRuleDigest, *input.OffsiteG008EvidenceDigest} {
		if len(digest) != 71 || !strings.HasPrefix(digest, "sha256:") {
			return nil, failure.New("INPUT_INVALID", "server-config", false)
		}
		if _, err := hex.DecodeString(strings.TrimPrefix(digest, "sha256:")); err != nil {
			return nil, failure.New("INPUT_INVALID", "server-config", false)
		}
	}
	return &OffsiteBackup{Endpoint: *input.OffsiteEndpoint, Bucket: *input.OffsiteBucket, Prefix: *input.OffsitePrefix,
		ParentReferenceID: *input.OffsiteParentReferenceID, ParentFingerprint: *input.OffsiteParentFingerprint,
		RuleDigest: *input.OffsiteRuleDigest, G008EvidenceDigest: *input.OffsiteG008EvidenceDigest}, nil
}

// convertLocalBackup enforces the all-or-none backup profile triplet. Absent
// (all three nil) disables local backup. A partial configuration fails closed.
// Each path must be absolute, clean and non-root, and the two backup roots must
// differ. Live path/mode/filesystem/executable identity is rechecked before any
// effect by the platform-specific preflight; these are the structural checks.
func convertLocalBackup(input generated.ServerProfile) (*LocalBackup, error) {
	present := 0
	for _, value := range []*string{input.StandardBackupRoot, input.CriticalBackupRoot, input.ResticBinaryPath, input.CustodyPolicyPath} {
		if value != nil {
			present++
		}
	}
	if present == 0 {
		return nil, nil
	}
	if present != 4 {
		return nil, failure.New("INPUT_INVALID", "server-config", false)
	}
	standard, critical, binary, custody := *input.StandardBackupRoot, *input.CriticalBackupRoot, *input.ResticBinaryPath, *input.CustodyPolicyPath
	for _, candidate := range []string{standard, critical, binary, custody} {
		if len(candidate) < 2 || len(candidate) > 4096 || strings.ContainsRune(candidate, 0) ||
			!filepath.IsAbs(candidate) || filepath.Clean(candidate) != candidate || candidate == string(filepath.Separator) {
			return nil, failure.New("INPUT_INVALID", "server-config", false)
		}
	}
	if standard == critical || standard == binary || critical == binary || custody == standard || custody == critical || custody == binary {
		return nil, failure.New("INPUT_INVALID", "server-config", false)
	}
	return &LocalBackup{StandardRoot: standard, CriticalRoot: critical, ResticBinaryPath: binary, CustodyPolicyPath: custody,
		SourceID: backupidentity.ControlDatabaseSource, StandardRepositoryID: backupidentity.StandardRepository,
		CriticalRepositoryID: backupidentity.CriticalRepository}, nil
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
