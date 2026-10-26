// Package workloadrecovery executes one finite cold Docker stack recovery.
package workloadrecovery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter/serviceruntime"
	"github.com/vegastack/vegastack-labs/internal/backup"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/servicerecovery"
)

func invalid() error { return servicerecovery.Invalid() }
func blocked() error { return servicerecovery.Blocked() }
func unavailable() error {
	return failure.New(generated.ErrorCodeDependencyUnavailable, "workload-recovery", false)
}

type Config struct {
	Profile                                           generated.ServiceRecoveryProfile
	Source, Target                                    serviceruntime.Target
	SourceCredential, TargetCredential, RepositoryKey *credentialref.Value
	Runner                                            backup.ResticRunner
	Check                                             func(context.Context) error
	VerifyRegistry                                    func(context.Context, http.RoundTripper) (string, error)
	RouteProof                                        func(context.Context) error
}
type archive struct {
	File, ContentDigest, ArchiveDigest string
	Bytes                              int64
}
type manifest struct {
	Schema, ConfigurationDigest, PointID, PolicyID, ServiceID string
	RecoveryEpoch                                             int64
	Archives                                                  []archive
}

func fileDigest(p string) (string, error) {
	f, e := os.Open(p)
	if e != nil {
		return "", unavailable()
	}
	defer f.Close()
	h := sha256.New()
	if _, e = io.Copy(h, f); e != nil {
		return "", unavailable()
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}
func privateDirectory(root string) error {
	st, e := os.Lstat(root)
	if e != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm()&0077 != 0 || !ownedDirectory(st) {
		return blocked()
	}
	return nil
}
func checkInventory(ctx context.Context, p *peer, profile generated.ServiceRecoveryProfile, target, requireStopped bool) ([]string, error) {
	project := profile.SourceProject
	if target {
		project = profile.TargetProject
	}
	ids, e := p.list(ctx, project)
	if e != nil {
		return nil, e
	}
	expected := make([]string, 0, len(profile.Components))
	running := []string{}
	for _, c := range profile.Components {
		id := c.SourceContainerID
		if target {
			id = c.TargetContainerID
		}
		expected = append(expected, id)
		v, e := p.inspect(ctx, id)
		if e != nil || v.ID != id || !p.imageMatches(ctx, v.Image, c.ImageDigest) || v.Project != project || len(v.Mounts) != len(c.Mounts) || v.Restart != "no" {
			return nil, blocked()
		}
		if requireStopped && v.Running {
			return nil, blocked()
		}
		if v.Running {
			running = append(running, id)
		}
		for _, m := range c.Mounts {
			found := false
			for _, actual := range v.Mounts {
				source := actual.Source
				if actual.Type == "volume" {
					source = actual.Name
				}
				want := m.Source
				if target {
					want = m.TargetSource
				}
				if actual.Type == m.Type && source == want && actual.Destination == m.Destination {
					found = true
					break
				}
			}
			if !found {
				return nil, blocked()
			}
		}
		if target {
			if len(v.Networks) == 0 {
				return nil, blocked()
			}
			for _, n := range v.Networks {
				if n.NetworkID == "" || !p.networkInternal(ctx, n.NetworkID) {
					return nil, blocked()
				}
			}
			for _, ports := range v.Ports {
				for _, b := range ports {
					if b.HostIP != "127.0.0.1" && b.HostIP != "::1" {
						return nil, blocked()
					}
				}
			}
		}
	}
	sort.Strings(expected)
	allowed := map[string]bool{}
	for _, id := range expected {
		allowed[id] = true
	}
	for _, component := range profile.Components {
		for _, m := range component.Mounts {
			storage := m.Source
			if target {
				storage = m.TargetSource
			}
			holders, e := p.holders(ctx, storage)
			if e != nil || len(holders) == 0 {
				return nil, blocked()
			}
			for _, holder := range holders {
				if !allowed[holder] {
					return nil, blocked()
				}
			}
		}
	}
	if strings.Join(ids, ",") != strings.Join(expected, ",") {
		return nil, blocked()
	}
	return running, nil
}
func healthy(ctx context.Context, p *peer, ids []string) (string, error) {
	deadline := time.Now().Add(60 * time.Second)
	for {
		all := true
		views := []inspected{}
		for _, id := range ids {
			v, e := p.inspect(ctx, id)
			if e != nil {
				return "", e
			}
			if !v.Running || v.Health != "healthy" {
				all = false
			}
			views = append(views, v)
		}
		if all {
			return servicerecovery.Digest(views), nil
		}
		if time.Now().After(deadline) {
			return "", blocked()
		}
		select {
		case <-ctx.Done():
			return "", unavailable()
		case <-time.After(100 * time.Millisecond):
		}
	}
}
func captureOne(ctx context.Context, p *peer, id, dest, file string, max int64, empty bool) (archive, error) {
	f, e := os.OpenFile(file, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return archive{}, unavailable()
	}
	e = p.capture(ctx, id, dest, f, max)
	closeErr := f.Close()
	if e != nil {
		return archive{}, e
	}
	if closeErr != nil {
		return archive{}, unavailable()
	}
	digest, size, e := archiveProof(file, max, empty)
	if e != nil {
		return archive{}, e
	}
	hash, e := fileDigest(file)
	return archive{File: filepath.Base(file), ContentDigest: digest, ArchiveDigest: hash, Bytes: size}, e
}
func Execute(ctx context.Context, q generated.ServiceRecoveryRequest, previous generated.ServiceRecoveryRecord, lease backup.WriterLease, c Config) (out servicerecovery.Outcome, err error) {
	started := time.Now()
	defer func() {
		out.ElapsedSeconds = int64(time.Since(started) / time.Second)
		if out.SourceImageDigests == nil {
			out.SourceImageDigests = []string{}
		}
		if out.Status == "succeeded" {
			for _, component := range c.Profile.Components {
				out.SourceImageDigests = append(out.SourceImageDigests, component.ImageDigest)
			}
		}
	}()
	out = servicerecovery.Outcome{Status: "partial", NextAction: "retry-with-new-plan"}
	if servicerecovery.ValidateRequest(q) != nil || servicerecovery.ValidateProfile(c.Profile) != nil || c.Profile.Binding != q.Binding || c.Source.HostID != q.Binding.SourceHostID || c.Target.HostID != q.Binding.TargetHostID || c.Source.ExpectedMachineIDDigest == c.Target.ExpectedMachineIDDigest || c.Check == nil || c.Runner == nil || c.RepositoryKey == nil {
		return out, invalid()
	}
	if e := c.Check(ctx); e != nil {
		return out, e
	}
	if q.Action == "recovery-after-writers" {
		out.NextAction = "roll-forward-required"
		return out, blocked()
	}
	if q.Action == "migration-cutover" || q.Action == "rollback-before-writers" {
		return migrate(ctx, q, previous, c)
	}
	if privateDirectory(c.Profile.ExchangeRoot) != nil || privateDirectory(c.Profile.RepositoryRoot) != nil {
		return out, blocked()
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(c.Profile.RecoveryObjectiveSeconds)*time.Second)
	defer cancel()
	source, e := connect(ctx, c.Source, c.SourceCredential, c.Check)
	if e != nil {
		return out, e
	}
	defer source.close()
	if q.Action == "backup" || q.Action == "migration-freeze" {
		return capture(ctx, q, source, lease, c)
	}
	if previous.Status != "succeeded" || (previous.Request.Action != "backup" && previous.Request.Action != "migration-freeze") || previous.BackupPointID != q.BackupPointID || previous.Request.Binding != q.Binding || previous.Request.RecoveryEpoch != q.RecoveryEpoch || (!previous.SourceResumed && !previous.SourceFenced) {
		return out, blocked()
	}
	return restore(ctx, q, previous, lease, c)
}
func capture(ctx context.Context, q generated.ServiceRecoveryRequest, source *peer, lease backup.WriterLease, c Config) (out servicerecovery.Outcome, err error) {
	out = servicerecovery.Outcome{Status: "partial", NextAction: "retry-with-new-plan"}
	running, e := checkInventory(ctx, source, c.Profile, false, false)
	if e != nil {
		return out, e
	}
	// Recovery cleanup is part of the approved cold capture and must run after
	// cancellation or authority loss. It can only restart the original exact set.
	stoppedAttempted := false
	defer func() {
		if !stoppedAttempted || (q.Action == "migration-freeze" && out.Status == "succeeded" && err == nil) {
			return
		}
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 90*time.Second)
		defer cancel()
		p, e := connect(cleanup, c.Source, c.SourceCredential, func(context.Context) error { return nil })
		if e != nil {
			out.Status = "partial"
			err = unavailable()
			return
		}
		defer p.close()
		if e = p.start(cleanup, running); e != nil {
			out.Status = "partial"
			err = e
			return
		}
		proof, e := healthy(cleanup, p, running)
		if e != nil {
			out.Status = "partial"
			err = e
			return
		}
		out.SourceResumed = true
		if out.RuntimeDigest == "" {
			out.RuntimeDigest = proof
		}
	}()
	stoppedAttempted = true
	if e = source.stop(ctx, running); e != nil {
		return out, e
	}
	if _, e = checkInventory(ctx, source, c.Profile, false, true); e != nil {
		return out, e
	}
	stage, e := os.MkdirTemp(c.Profile.ExchangeRoot, ".vsk-workload-staging-")
	if e != nil {
		return out, unavailable()
	}
	defer os.RemoveAll(stage)
	m := manifest{Schema: "vegastack-labs.dev/workload-cold-manifest-v1", ConfigurationDigest: q.Binding.ConfigurationDigest, PointID: "workload-point-" + servicerecovery.Digest(q)[7:39], PolicyID: q.Binding.PolicyID, ServiceID: q.Definition.ServiceID, RecoveryEpoch: q.RecoveryEpoch, Archives: []archive{}}
	remaining := c.Profile.MaximumBytes
	for _, component := range c.Profile.Components {
		for _, mount := range component.Mounts {
			file := filepath.Join(stage, "mount-"+strconvIndex(len(m.Archives))+".tar")
			a, e := captureOne(ctx, source, component.SourceContainerID, mount.Destination, file, remaining, false)
			if e != nil {
				return out, e
			}
			remaining -= a.Bytes
			m.Archives = append(m.Archives, a)
		}
	}
	if _, e = checkInventory(ctx, source, c.Profile, false, true); e != nil {
		return out, e
	}
	raw, e := json.Marshal(m)
	if e != nil || os.WriteFile(filepath.Join(stage, "manifest.json"), raw, 0600) != nil {
		return out, unavailable()
	}
	base, closeRepo, e := repository(ctx, lease, c, false)
	if e != nil {
		return out, e
	}
	defer closeRepo()
	base.Mode = "config"
	if _, e = c.Runner.Run(ctx, base, c.RepositoryKey); e != nil {
		entries, listErr := os.ReadDir(c.Profile.RepositoryRoot)
		if listErr != nil || len(entries) != 0 {
			return out, e
		}
		base.Mode = "init"
		if _, e = c.Runner.Run(ctx, base, c.RepositoryKey); e != nil {
			return out, e
		}
		base.Mode = "config"
		if _, e = c.Runner.Run(ctx, base, c.RepositoryKey); e != nil {
			return out, e
		}
	}
	base.Mode = "backup"
	base.SnapshotPath = stage
	result, e := c.Runner.Run(ctx, base, c.RepositoryKey)
	if e != nil {
		return out, e
	}
	if result.RepositoryFormat != 2 || result.SnapshotCount != 1 || result.SnapshotID == "" {
		return out, invalid()
	}
	base.Mode = "snapshots"
	snapshots, e := c.Runner.Run(ctx, base, c.RepositoryKey)
	if e != nil || len(snapshots.SnapshotPaths[result.SnapshotID]) != 1 || snapshots.SnapshotPaths[result.SnapshotID][0] != stage {
		return out, invalid()
	}
	base.Mode = "check-full"
	if _, e = c.Runner.Run(ctx, base, c.RepositoryKey); e != nil {
		return out, e
	}
	out.Status = "succeeded"
	out.NextAction = "none"
	out.BackupPointID = m.PointID
	out.SnapshotID = result.SnapshotID
	out.SourceFenced = q.Action == "migration-freeze"
	if out.SourceFenced {
		out.RuntimeDigest = servicerecovery.Digest([]string{"source-stack-stopped", q.Binding.ConfigurationDigest})
	}
	out.ManifestDigest = servicerecovery.Digest(m)
	out.ContentDigest = servicerecovery.Digest(m.Archives)
	return out, nil
}
func strconvIndex(n int) string {
	const digits = "0123456789"
	if n < 10 {
		return string(digits[n])
	}
	return strconvIndex(n/10) + string(digits[n%10])
}
func restore(ctx context.Context, q generated.ServiceRecoveryRequest, previous generated.ServiceRecoveryRecord, lease backup.WriterLease, c Config) (out servicerecovery.Outcome, err error) {
	out = servicerecovery.Outcome{Status: "partial", NextAction: "recovery-required", BackupPointID: previous.BackupPointID, SnapshotID: previous.SnapshotID, ManifestDigest: previous.ManifestDigest, ContentDigest: previous.ContentDigest}
	base, closeRepo, e := repository(ctx, lease, c, true)
	if e != nil {
		return out, e
	}
	defer closeRepo()
	base.Mode = "snapshots"
	snapshots, e := c.Runner.Run(ctx, base, c.RepositoryKey)
	if e != nil {
		return out, e
	}
	paths := snapshots.SnapshotPaths[previous.SnapshotID]
	if len(paths) != 1 || filepath.Dir(paths[0]) != c.Profile.ExchangeRoot || !strings.HasPrefix(filepath.Base(paths[0]), ".vsk-workload-staging-") {
		return out, invalid()
	}
	base.Mode = "check-full"
	if _, e = c.Runner.Run(ctx, base, c.RepositoryKey); e != nil {
		return out, e
	}
	root, e := os.MkdirTemp(c.Profile.ExchangeRoot, ".vsk-backup-verify-")
	if e != nil {
		return out, unavailable()
	}
	defer os.RemoveAll(root)
	base.Mode = "restore"
	base.SnapshotID = previous.SnapshotID
	base.RestoreTarget = root
	if _, e = c.Runner.Run(ctx, base, c.RepositoryKey); e != nil {
		return out, e
	}
	stage := filepath.Join(root, strings.TrimPrefix(paths[0], string(filepath.Separator)))
	raw, e := os.ReadFile(filepath.Join(stage, "manifest.json"))
	if e != nil || len(raw) > 1<<20 {
		return out, invalid()
	}
	var m manifest
	if json.Unmarshal(raw, &m) != nil || servicerecovery.Digest(m) != previous.ManifestDigest || servicerecovery.Digest(m.Archives) != previous.ContentDigest || m.PointID != q.BackupPointID || m.ConfigurationDigest != q.Binding.ConfigurationDigest || m.RecoveryEpoch != q.RecoveryEpoch {
		return out, invalid()
	}
	count := 0
	for _, component := range c.Profile.Components {
		count += len(component.Mounts)
	}
	if count != len(m.Archives) {
		return out, invalid()
	}
	for i, a := range m.Archives {
		if a.File != "mount-"+strconvIndex(i)+".tar" {
			return out, invalid()
		}
		f := filepath.Join(stage, a.File)
		hash, e := fileDigest(f)
		if e != nil || hash != a.ArchiveDigest {
			return out, invalid()
		}
		digest, size, e := archiveProof(f, c.Profile.MaximumBytes, false)
		if e != nil || digest != a.ContentDigest || size != a.Bytes {
			return out, invalid()
		}
	}
	target, e := connect(ctx, c.Target, c.TargetCredential, c.Check)
	if e != nil {
		return out, e
	}
	defer target.close()
	if _, e = checkInventory(ctx, target, c.Profile, true, true); e != nil {
		return out, e
	}
	scratch, e := os.MkdirTemp(c.Profile.ExchangeRoot, ".vsk-workload-empty-")
	if e != nil {
		return out, unavailable()
	}
	defer os.RemoveAll(scratch)
	i := 0
	for _, component := range c.Profile.Components {
		for _, mount := range component.Mounts {
			_, e = captureOne(ctx, target, component.TargetContainerID, mount.Destination, filepath.Join(scratch, "empty-"+strconvIndex(i)+".tar"), c.Profile.MaximumBytes, true)
			if e != nil {
				return out, e
			}
			i++
		}
	}
	i = 0
	for _, component := range c.Profile.Components {
		for _, mount := range component.Mounts {
			if _, e = checkInventory(ctx, target, c.Profile, true, true); e != nil {
				return out, e
			}
			f, e := os.Open(filepath.Join(stage, m.Archives[i].File))
			if e != nil {
				return out, unavailable()
			}
			e = target.restore(ctx, component.TargetContainerID, mount.Destination, io.LimitReader(f, m.Archives[i].Bytes))
			_ = f.Close()
			if e != nil {
				return out, e
			}
			i++
		}
	}
	i = 0
	for _, component := range c.Profile.Components {
		for _, mount := range component.Mounts {
			a, e := captureOne(ctx, target, component.TargetContainerID, mount.Destination, filepath.Join(scratch, "restored-"+strconvIndex(i)+".tar"), c.Profile.MaximumBytes, false)
			if e != nil || a.ContentDigest != m.Archives[i].ContentDigest {
				return out, invalid()
			}
			i++
		}
	}
	ids := []string{}
	for _, component := range c.Profile.Components {
		ids = append(ids, component.TargetContainerID)
	}
	if e = target.start(ctx, ids); e != nil {
		return out, e
	}
	proof, e := healthy(ctx, target, ids)
	if e != nil {
		return out, e
	}
	if c.Profile.Binding.DataClass == "registry" {
		if c.VerifyRegistry == nil {
			return out, blocked()
		}
		transport, e := target.registryTransport(ctx, c.Profile)
		if e != nil {
			return out, e
		}
		defer transport.CloseIdleConnections()
		registryProof, e := c.VerifyRegistry(ctx, transport)
		if e != nil || registryProof == "" {
			return out, blocked()
		}
		proof = servicerecovery.Digest([]string{proof, registryProof})
	}
	if _, e = checkInventory(ctx, target, c.Profile, true, false); e != nil {
		return out, e
	}
	out.RuntimeDigest = proof
	out.Status = "succeeded"
	out.NextAction = "none"
	out.SourceResumed = previous.SourceResumed
	out.SourceFenced = previous.SourceFenced
	out.IsolatedRestoreVerified = true
	return out, nil
}
func migrate(ctx context.Context, q generated.ServiceRecoveryRequest, previous generated.ServiceRecoveryRecord, c Config) (out servicerecovery.Outcome, err error) {
	out = servicerecovery.Outcome{Status: "blocked", NextAction: "route-proof-required"}
	if !previous.IsolatedRestoreVerified || previous.Status != "succeeded" || previous.Request.Binding != q.Binding || previous.Request.RecoveryEpoch != q.RecoveryEpoch || previous.BackupPointID != q.BackupPointID {
		return out, blocked()
	}
	// A state-only phase flag cannot switch traffic. Until the independent owned
	// ingress journal proves the exact route AND its current writer fence, no
	// source is stopped or restarted. Post-writer reversal is never permitted.
	if previous.TargetWritersEnabled {
		out.NextAction = "roll-forward-required"
		return out, blocked()
	}
	if !previous.SourceFenced || c.RouteProof == nil || c.RouteProof(ctx) != nil {
		return out, blocked()
	}
	// Route mutation and source fencing must use their own exact approved plans.
	// The callback must prove both before this operation can finalize the result.
	source, e := connect(ctx, c.Source, c.SourceCredential, c.Check)
	if e != nil {
		return out, e
	}
	defer source.close()
	target, e := connect(ctx, c.Target, c.TargetCredential, c.Check)
	if e != nil {
		return out, e
	}
	defer target.close()
	if q.Action == "rollback-before-writers" {
		if _, e = checkInventory(ctx, target, c.Profile, true, true); e != nil {
			return out, e
		}
		ids := []string{}
		for _, component := range c.Profile.Components {
			ids = append(ids, component.SourceContainerID)
		}
		if e = source.start(ctx, ids); e != nil {
			return out, e
		}
		proof, e := healthy(ctx, source, ids)
		if e != nil {
			return out, e
		}
		out.SourceResumed = true
		out.RuntimeDigest = proof
	} else {
		if _, e = checkInventory(ctx, source, c.Profile, false, true); e != nil {
			return out, e
		}
		ids := []string{}
		for _, component := range c.Profile.Components {
			ids = append(ids, component.TargetContainerID)
		}
		proof, e := healthy(ctx, target, ids)
		if e != nil {
			return out, e
		}
		out.RuntimeDigest = proof
		out.TargetWritersEnabled = true
		out.SourceFenced = true
	}
	out.Status = "succeeded"
	out.NextAction = "none"
	out.BackupPointID = previous.BackupPointID
	out.SnapshotID = previous.SnapshotID
	out.ManifestDigest = previous.ManifestDigest
	out.ContentDigest = previous.ContentDigest
	out.IsolatedRestoreVerified = true
	return out, nil
}
