// Package servicerecovery contains the finite cold-stack recovery contract.
package servicerecovery

import (
	"encoding/json"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
)

const AdapterID = "core.service-recovery"
const Operation = "service.recover"
const OperationID = "service-recovery"
const ConsistencyProcedureID = "docker-stack-cold-v1"

type Policy struct {
	Binding                          generated.ServiceRecoveryBinding
	PlatformOwnerID, TargetServiceID string
}
type Outcome struct {
	SourceImageDigests                                                                          []string
	ElapsedSeconds                                                                              int64
	Status, BackupPointID, SnapshotID, ManifestDigest, ContentDigest, RuntimeDigest, NextAction string
	SourceResumed, SourceFenced, IsolatedRestoreVerified, TargetWritersEnabled                  bool
}

func Digest(v any) string { return hostaction.Digest(v) }
func Invalid() error      { return failure.New(generated.ErrorCodeInputInvalid, "service-recovery", false) }
func Blocked() error {
	return failure.New(generated.ErrorCodePrerequisiteBlocked, "service-recovery", false)
}
func ValidateRequest(q generated.ServiceRecoveryRequest) error {
	raw, e := json.Marshal(q)
	if e != nil || generated.ValidateContractJSON(generated.SchemaIDServiceRecoveryRequest, raw, generated.ContractExact) != nil || q.Definition.ServiceID != q.Binding.ServiceID || q.Definition.HostID != q.Binding.SourceHostID || q.Binding.ConsistencyProcedureID != ConsistencyProcedureID {
		return Invalid()
	}
	if q.Action != "backup" && q.Action != "migration-freeze" && q.BackupPointID == "" {
		return Invalid()
	}
	if (q.Action == "backup" || q.Action == "migration-freeze") && q.BackupPointID != "" {
		return Invalid()
	}
	return nil
}

var idRE = regexp.MustCompile(`^[a-f0-9]{64}$`)
var projectRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,127}$`)
var digestRE = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

func safeMount(p string) bool {
	return path.IsAbs(p) && path.Clean(p) == p && p != "/" && !strings.ContainsAny(p, "\x00\r\n")
}
func ValidateProfile(p generated.ServiceRecoveryProfile) error {
	if p.Binding.DataClass == "platform" && p.PlatformOwnerID == "" {
		return Invalid()
	}
	if p.Binding.ConsistencyProcedureID != ConsistencyProcedureID || p.Binding.SourceHostID == p.Binding.TargetHostID || p.TargetServiceID == p.Binding.ServiceID || !projectRE.MatchString(p.SourceProject) || !projectRE.MatchString(p.TargetProject) || p.SourceProject == p.TargetProject || p.MaximumBytes < 1 || p.MaximumBytes > 1<<40 || p.RecoveryObjectiveSeconds < 1 || p.RecoveryObjectiveSeconds > 86400 || len(p.Components) == 0 || len(p.Components) > 32 {
		return Invalid()
	}
	if p.SourceReferenceID == p.TargetReferenceID || p.SourceReferenceID == p.RepositoryKeyReferenceID || p.TargetReferenceID == p.RepositoryKeyReferenceID {
		return Invalid()
	}
	for _, v := range []string{p.RepositoryRoot, p.ExchangeRoot, p.ResticBinaryPath} {
		if !filepath.IsAbs(v) || filepath.Clean(v) != v || v == string(filepath.Separator) {
			return Invalid()
		}
	}
	seen := map[string]bool{}
	sources := map[string]string{}
	targets := map[string]string{}
	for _, c := range p.Components {
		if !idRE.MatchString(c.SourceContainerID) || !idRE.MatchString(c.TargetContainerID) || c.SourceContainerID == c.TargetContainerID || seen[c.SourceContainerID] || seen[c.TargetContainerID] || !digestRE.MatchString(c.ImageDigest) || len(c.Mounts) > 64 {
			return Invalid()
		}
		seen[c.SourceContainerID] = true
		seen[c.TargetContainerID] = true
		destinations := map[string]bool{}
		for _, m := range c.Mounts {
			if !safeMount(m.Destination) || destinations[m.Destination] || m.Source == "" || m.TargetSource == "" || strings.ContainsAny(m.Source+m.TargetSource, "\x00\r\n") {
				return Invalid()
			}
			destinations[m.Destination] = true
			sk := m.Type + ":" + m.Source
			tk := m.Type + ":" + m.TargetSource
			// Shared mounts must map consistently to one isolated target storage identity.
			if (sources[sk] != "" && sources[sk] != tk) || (targets[tk] != "" && targets[tk] != sk) {
				return Invalid()
			}
			sources[sk] = tk
			targets[tk] = sk
			if m.Type == "bind" && (!safeMount(m.Source) || !safeMount(m.TargetSource)) {
				return Invalid()
			}
			for other := range destinations {
				if other != m.Destination && (strings.HasPrefix(other, m.Destination+"/") || strings.HasPrefix(m.Destination, other+"/")) {
					return Invalid()
				}
			}
		}
	}
	if len(sources) == 0 {
		return Invalid()
	}
	if p.RepositoryURL != "" {
		return Invalid()
	}
	if p.Binding.DataClass == "registry" && (p.HarborOrigin == "" || p.HarborProject == "" || p.HarborRepository == "" || !digestRE.MatchString(p.HarborArtifactDigest) || p.HarborReferenceID == "" || p.HarborUsername == "") {
		return Invalid()
	}
	return nil
}
