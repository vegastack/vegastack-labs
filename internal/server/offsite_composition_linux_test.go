//go:build linux

package server

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/backup"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localapi"
	runengine "github.com/vegastack/vegastack-labs/internal/run"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type composedOffsiteSource struct{}

func (composedOffsiteSource) VerifiedCriticalPoint(context.Context, string) (backup.VerifiedCriticalPoint, error) {
	return backup.VerifiedCriticalPoint{}, errors.New("not executed by composition test")
}

type composedOffsiteSpecs struct{}

func (composedOffsiteSpecs) ResolveOffsiteDeclaration(context.Context, adapter.Operation, adapter.ExactExecutionBinding) (backup.OffsiteRunDeclaration, backup.OffsitePolicy, error) {
	return backup.OffsiteRunDeclaration{}, backup.OffsitePolicy{}, errors.New("not executed by composition test")
}
func (composedOffsiteSpecs) PrepareOffsiteRun(context.Context, backup.OffsiteRunDeclaration, adapter.Operation, adapter.ExactExecutionBinding, []*credentialref.Value) (backup.OffsiteRunSpec, error) {
	return backup.OffsiteRunSpec{}, errors.New("not executed by composition test")
}

func TestOperationsRunComposesOnlyQualifiedOffsiteRuntime(t *testing.T) {
	for _, qualified := range []bool{false, true} {
		t.Run(map[bool]string{false: "unqualified", true: "qualified"}[qualified], func(t *testing.T) {
			operations, profile, configPath, factory := productionOperationsFixture(t, generated.RemoteReadProfile{})
			content, err := os.ReadFile(configPath)
			if err != nil {
				t.Fatal(err)
			}
			var generatedProfile generated.ServerProfile
			if json.Unmarshal(content, &generatedProfile) != nil {
				t.Fatal("decode generated profile")
			}
			directory := filepath.Dir(configPath)
			standard, critical := filepath.Join(directory, "standard"), filepath.Join(directory, "critical")
			binary, custody := filepath.Join(directory, "restic"), filepath.Join(directory, "custody.json")
			endpoint, bucket, prefix, parent := "https://0123456789abcdef0123456789abcdef.r2.cloudflarestorage.com", "bucket-a", "critical", "parent-a"
			digest := "sha256:" + strings.Repeat("a", 64)
			generatedProfile.StandardBackupRoot, generatedProfile.CriticalBackupRoot = &standard, &critical
			generatedProfile.ResticBinaryPath, generatedProfile.CustodyPolicyPath = &binary, &custody
			generatedProfile.OffsiteEndpoint, generatedProfile.OffsiteBucket, generatedProfile.OffsitePrefix = &endpoint, &bucket, &prefix
			generatedProfile.OffsiteParentReferenceID, generatedProfile.OffsiteParentFingerprint = &parent, &digest
			observer := "observer-a"
			generatedProfile.OffsiteObserverReferenceID = &observer
			generatedProfile.OffsiteRuleDigest, generatedProfile.OffsiteG008EvidenceDigest = &digest, &digest
			account := "0123456789abcdef0123456789abcdef"
			availableBytes, availablePUTs, availableLISTs := int64(1), int64(1), int64(1)
			ruleCount, retainedGenerations := int64(1), int64(1)
			generatedProfile.OffsiteAccountID = &account
			generatedProfile.OffsiteQualificationDigest = &digest
			generatedProfile.OffsitePutCutoffDigest = &digest
			generatedProfile.OffsiteMultipartCutoffDigest = &digest
			generatedProfile.OffsiteAvailableBytes = &availableBytes
			generatedProfile.OffsiteAvailablePUTs = &availablePUTs
			generatedProfile.OffsiteAvailableLISTs = &availableLISTs
			generatedProfile.OffsiteRuleCount = &ruleCount
			generatedProfile.OffsiteRetainedGenerations = &retainedGenerations
			writeProtectedJSON(t, configPath, generatedProfile)

			runners := NewProfileOffsiteRunnerSource(func(_ context.Context, _ serverconfig.Profile, authority *store.Store, evidence generated.GateEvidence) (runengine.OffsiteCopyRunner, error) {
				if evidence.ProofClass != "live" {
					return nil, errors.New("non-live evidence")
				}
				return backup.NewOffsiteWorkflowRunner(composedOffsiteSource{}, composedOffsiteSpecs{}, backup.NewSQLCatalog(authority))
			})
			runners.resolve = func(context.Context, *store.Store, *serverconfig.OffsiteBackup, time.Time) (generated.GateEvidence, error) {
				if !qualified {
					return generated.GateEvidence{}, errors.New("G-008 unavailable")
				}
				return generated.GateEvidence{ProofClass: "live"}, nil
			}
			registry := adapter.NewRegistry()
			operations.offsiteEffect = NewProductionOffsiteEffectFactory(runners)
			operations.newAdapterRegistry = func() *adapter.Registry { return registry }
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- operations.Run(ctx, configPath) }()
			_ = awaitProductionSummary(t, localapi.NewClient(factory), profile, done)
			_, resolveErr := registry.Resolve(runengine.OffsiteAdapterID)
			if qualified && resolveErr != nil {
				t.Fatalf("qualified runtime not registered: %v", resolveErr)
			}
			if !qualified && resolveErr == nil {
				t.Fatal("unqualified runtime registered")
			}
			cancel()
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}
