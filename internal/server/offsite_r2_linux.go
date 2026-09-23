//go:build linux

package server

import (
	"context"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapters/r2"
	"github.com/vegastack/vegastack-labs/internal/backup"
	"github.com/vegastack/vegastack-labs/internal/generated"
	runengine "github.com/vegastack/vegastack-labs/internal/run"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/store"
)

func NewLabsR2Runner(_ context.Context, profile serverconfig.Profile, authority *store.Store, evidence generated.GateEvidence) (runengine.OffsiteCopyRunner, error) {
	offsite := profile.OffsiteBackup
	runtime, err := r2.NewProductionRuntime(r2.RuntimeConfig{Authority: authority, Endpoint: offsite.Endpoint, Bucket: offsite.Bucket, Prefix: offsite.Prefix, AccountID: offsite.AccountID,
		ParentReferenceID: offsite.ParentReferenceID, ParentFingerprint: offsite.ParentFingerprint, ObserverReferenceID: offsite.ObserverReferenceID, RuleDigest: offsite.RuleDigest,
		QualificationDigest: offsite.QualificationDigest, PutCutoffDigest: offsite.PutCutoffDigest, MultipartCutoffDigest: offsite.MultipartCutoffDigest,
		CustodyPolicyPath: profile.LocalBackup.CustodyPolicyPath, ResticBinaryPath: profile.LocalBackup.ResticBinaryPath,
		AvailableBytes: offsite.AvailableBytes, AvailablePUTs: offsite.AvailablePUTs, AvailableLISTs: offsite.AvailableLISTs, RuleCount: offsite.RuleCount, RuleLimit: 1000, RetainedGenerations: offsite.RetainedGenerations,
		Evidence: evidence, Clock: time.Now})
	if err != nil {
		return nil, err
	}
	specs, err := backup.NewSQLRunSpecSource(authority, runtime, offsite.Endpoint, offsite.Bucket, offsite.Prefix, offsite.ParentReferenceID, offsite.ObserverReferenceID, offsite.RuleDigest, offsite.G008EvidenceDigest)
	if err != nil {
		return nil, err
	}
	return backup.NewOffsiteWorkflowRunner(r2.StoreSource{Catalog: store.NewBackupRepository(authority)}, specs, backup.NewSQLCatalog(authority))
}
