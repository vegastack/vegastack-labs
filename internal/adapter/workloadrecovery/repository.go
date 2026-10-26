package workloadrecovery

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/vegastack/vegastack-labs/internal/backup"
)

type sessionVerifier struct {
	check func(context.Context) error
	ctx   context.Context
	lease backup.WriterLease
}

func (v sessionVerifier) VerifyWriterLease(l backup.WriterLease, now time.Time) error {
	if l != v.lease || !now.Before(l.MaximumExpiresAt) {
		return blocked()
	}
	return v.check(v.ctx)
}
func (v sessionVerifier) VerifyReadLease(l backup.ReadLease, now time.Time) error {
	if l.LeaseID != v.lease.LeaseID || l.RepositoryID != v.lease.RepositoryID || l.PointID != v.lease.PointID || l.RecoveryEpoch != v.lease.RecoveryEpoch || !now.Before(l.MaximumExpiresAt) {
		return blocked()
	}
	return v.check(v.ctx)
}

// repository reuses the existing peer-checked append-only/read-only UDS backend.
// Its lifetime and every object request are bound to the current exact run lease.
func repository(ctx context.Context, lease backup.WriterLease, c Config, read bool) (backup.ResticRequest, func(), error) {
	var req backup.ResticRequest
	if lease.LeaseID == "" || lease.PlanID == "" || lease.RunID == "" || lease.StepID == "" || lease.RepositoryID != c.Profile.RepositoryID || lease.PolicyID != c.Profile.Binding.PolicyID || lease.MaximumExpiresAt.IsZero() {
		return req, nil, blocked()
	}
	if privateDirectory(c.Profile.RepositoryRoot) != nil {
		return req, nil, blocked()
	}
	dir, e := os.MkdirTemp(c.Profile.ExchangeRoot, ".vsk-r-")
	if e != nil {
		return req, nil, unavailable()
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	socket := filepath.Join(dir, "r")
	listener, e := net.Listen("unix", socket)
	if e != nil {
		cleanup()
		return req, nil, unavailable()
	}
	verifier := sessionVerifier{c.Check, ctx, lease}
	var server *backup.RESTServer
	if read {
		server, e = backup.NewVerifierRESTServer(c.Profile.RepositoryRoot, uint32(os.Geteuid()), backup.ReadLease{LeaseID: lease.LeaseID, PointID: lease.PointID, RepositoryID: lease.RepositoryID, RecoveryEpoch: lease.RecoveryEpoch, MaximumExpiresAt: lease.MaximumExpiresAt}, verifier, time.Now)
	} else {
		server, e = backup.NewRESTServer(c.Profile.RepositoryRoot, uint32(os.Geteuid()), lease, verifier, time.Now)
	}
	if e != nil {
		_ = listener.Close()
		cleanup()
		return req, nil, e
	}
	serveCtx, cancel := context.WithCancel(ctx)
	go func() { _ = server.Serve(serveCtx, listener) }()
	closeRepo := func() { cancel(); _ = listener.Close(); cleanup() }
	req = backup.ResticRequest{BinaryPath: c.Profile.ResticBinaryPath, Architecture: c.Profile.Architecture, RepositoryURL: "http+unix://" + socket + ":/" + c.Profile.RepositoryID + "/", RepositoryID: c.Profile.RepositoryID, RepositoryClass: "critical", RepositoryRoot: c.Profile.RepositoryRoot, ExchangeRoot: c.Profile.ExchangeRoot, PolicyDigest: c.Profile.Binding.ConfigurationDigest, Lease: lease, OutputLimit: 4 << 20}
	return req, closeRepo, nil
}
