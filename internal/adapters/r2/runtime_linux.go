//go:build linux

package r2

import (
	"context"
	"crypto/rand"
	"errors"
	"net"
	"net/http"
	"runtime"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/backup"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type RuntimeConfig struct {
	Authority                                     *store.Store
	Endpoint, Bucket, Prefix, AccountID           string
	ParentReferenceID, ParentFingerprint          string
	ObserverReferenceID, RuleDigest               string
	QualificationDigest                           string
	PutCutoffDigest, MultipartCutoffDigest        string
	CustodyPolicyPath, ResticBinaryPath           string
	AvailableBytes, AvailablePUTs, AvailableLISTs int64
	RuleCount, RuleLimit, RetainedGenerations     int
	Evidence                                      generated.GateEvidence
	Clock                                         func() time.Time
	HTTPClient                                    *http.Client
}

type ProductionRuntime struct{ config RuntimeConfig }

func NewProductionRuntime(config RuntimeConfig) (*ProductionRuntime, error) {
	if config.Authority == nil || config.Endpoint == "" || config.Bucket == "" || config.Prefix == "" || config.AccountID == "" || config.ParentReferenceID == "" || config.ObserverReferenceID == "" || config.ParentReferenceID == config.ObserverReferenceID || config.CustodyPolicyPath != backup.CustodyPolicyPath || config.ResticBinaryPath == "" || config.Evidence.ProofClass != "live" {
		return nil, errors.New("r2 production runtime unavailable")
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	qualification := Qualification{AccountID: config.AccountID, Bucket: config.Bucket, Prefix: config.Prefix, ObserverReferenceID: config.ObserverReferenceID, RuleDigest: config.RuleDigest,
		AvailableBytes: config.AvailableBytes, AvailablePUTs: config.AvailablePUTs, AvailableLISTs: config.AvailableLISTs, RuleCount: config.RuleCount, RetainedGenerations: config.RetainedGenerations,
		PutCutoffCheckID: "r2-expired-put-denied", PutCutoffDigest: config.PutCutoffDigest, MultipartCutoffCheckID: "r2-expired-multipart-completion-denied", MultipartCutoffDigest: config.MultipartCutoffDigest}
	if DigestQualification(qualification) != config.QualificationDigest {
		return nil, errors.New("r2 qualification binding invalid")
	}
	return &ProductionRuntime{config: config}, nil
}

func (runtimeConfig *ProductionRuntime) PrepareOffsiteRun(ctx context.Context, declaration backup.OffsiteRunDeclaration, operation adapter.Operation, binding adapter.ExactExecutionBinding, values []*credentialref.Value) (backup.OffsiteRunSpec, error) {
	if runtimeConfig == nil || len(values) != 3 || values[0] == nil || values[1] == nil || values[2] == nil || declaration.ParentReferenceID != runtimeConfig.config.ParentReferenceID || declaration.ObserverReferenceID != runtimeConfig.config.ObserverReferenceID || declaration.RuleDigest != runtimeConfig.config.RuleDigest {
		return backup.OffsiteRunSpec{}, errors.New("r2 run preparation denied")
	}
	deadline, err := time.Parse(time.RFC3339, binding.MaximumExpiresAt)
	if err != nil || !runtimeConfig.config.Clock().Before(deadline) {
		return backup.OffsiteRunSpec{}, errors.New("r2 run deadline invalid")
	}
	retentionClock, err := time.Parse(time.RFC3339, runtimeConfig.config.Evidence.ObservedAt)
	if err != nil {
		return backup.OffsiteRunSpec{}, errors.New("r2 qualification time invalid")
	}
	retention, err := (RetentionClient{AccountID: runtimeConfig.config.AccountID, Bucket: runtimeConfig.config.Bucket, Client: runtimeConfig.config.HTTPClient, Clock: func() time.Time { return retentionClock },
		AvailableBytes: runtimeConfig.config.AvailableBytes, AvailablePUTs: runtimeConfig.config.AvailablePUTs, AvailableLISTs: runtimeConfig.config.AvailableLISTs,
		RuleCount: runtimeConfig.config.RuleCount, RuleLimit: runtimeConfig.config.RuleLimit, RetainedGenerations: runtimeConfig.config.RetainedGenerations}).Observe(ctx, declaration.GenerationID, runtimeConfig.config.Prefix+"/"+declaration.GenerationID, values[2].Bytes())
	if err != nil || retention.RuleDigest != declaration.RuleDigest {
		return backup.OffsiteRunSpec{}, errors.New("r2 retention qualification mismatch")
	}
	signer := LocalSigner{Endpoint: runtimeConfig.config.Endpoint, Bucket: runtimeConfig.config.Bucket, Clock: runtimeConfig.config.Clock}
	issuer := SessionIssuer{Signer: signer, Clock: runtimeConfig.config.Clock, ParentReferenceID: runtimeConfig.config.ParentReferenceID, ParentFingerprint: runtimeConfig.config.ParentFingerprint}
	readRequest := adapter.SessionRequest{RunID: binding.RunID, StepID: binding.StepID, PointID: declaration.SourcePointID, GenerationID: declaration.GenerationID, RecoveryEpoch: binding.RecoveryEpoch,
		Prefix: runtimeConfig.config.Prefix + "/" + declaration.GenerationID + "/", Actions: []string{"GetObject", "HeadObject", "ListObjectsV2"}, Deadline: deadline, TTL: time.Duration(declaration.SessionTTLSeconds) * time.Second}
	readRequest.ParentReferenceID, readRequest.ParentFingerprint = runtimeConfig.config.ParentReferenceID, runtimeConfig.config.ParentFingerprint
	readSession, err := issuer.Issue(ctx, readRequest, values[0])
	if err != nil {
		return backup.OffsiteRunSpec{}, err
	}
	readBearer := make([]byte, 32)
	if _, err := rand.Read(readBearer); err != nil {
		return backup.OffsiteRunSpec{}, err
	}
	readEndpoint, readIAMURI, err := serveOneRunEndpoint(issuer, values[0], readRequest, readBearer, runtimeConfig.config.Clock, nil)
	if err != nil {
		return backup.OffsiteRunSpec{}, err
	}
	observer := &runObserver{s3: S3Client{Endpoint: runtimeConfig.config.Endpoint, Bucket: runtimeConfig.config.Bucket, Client: runtimeConfig.config.HTTPClient, Clock: runtimeConfig.config.Clock}, credentials: sessionCredentials(readSession), prefix: readRequest.Prefix, maximumObjects: declaration.MaximumPUTs, maximumBytes: declaration.MaximumBytes, clock: runtimeConfig.config.Clock,
		readEndpoint: readEndpoint, readIAMURI: readIAMURI, readBearer: readBearer, password: values[1], binaryPath: runtimeConfig.config.ResticBinaryPath, repositoryURL: declaration.RepositoryURL, snapshotPath: declaration.SnapshotPath}

	writerRequest := readRequest
	writerRequest.Actions = append([]string(nil), allowedWriterActions...)
	bearer := make([]byte, 32)
	if _, err := rand.Read(bearer); err != nil {
		return backup.OffsiteRunSpec{}, err
	}
	endpoint, writerIAMURI, err := serveOneRunEndpoint(issuer, values[0], writerRequest, bearer, runtimeConfig.config.Clock, func() {
		observer.zero()
		_ = readEndpoint.Close()
	})
	if err != nil {
		_ = readEndpoint.Close()
		return backup.OffsiteRunSpec{}, err
	}

	maximum, _ := time.Parse(time.RFC3339, binding.MaximumExpiresAt)
	lease := backup.WriterLease{PlanID: binding.PlanID, PlanDigest: binding.PlanDigest, RunID: binding.RunID, StepID: binding.StepID, LeaseID: binding.LeaseID, RepositoryID: declaration.GenerationID, RepositoryClass: "critical-offsite", PointID: declaration.SourcePointID, TargetID: declaration.GenerationID, SourceRevision: declaration.StateRevision, RecoveryEpoch: binding.RecoveryEpoch, MaximumExpiresAt: maximum}
	authority := &custodyAuthority{repository: store.NewOffsiteRepository(runtimeConfig.config.Authority), stateRevision: binding.StateRevision, context: ctx}
	if err := authority.repository.BindCustodyLease(ctx, store.OffsiteCustodyBinding{PlanID: binding.PlanID, PlanDigest: binding.PlanDigest, RunID: binding.RunID, StepID: binding.StepID, LeaseID: binding.LeaseID, GenerationID: declaration.GenerationID, SourcePointID: declaration.SourcePointID, StateRevision: binding.StateRevision, RecoveryEpoch: binding.RecoveryEpoch, MaximumExpiresAt: maximum}); err != nil {
		_ = endpoint.Close()
		return backup.OffsiteRunSpec{}, err
	}
	session := backup.CustodySession{ProtocolVersion: backup.CustodyProtocolVersion, Role: "offsite-writer", PlanID: binding.PlanID, PlanDigest: binding.PlanDigest, RunID: binding.RunID, StepID: binding.StepID, LeaseID: binding.LeaseID,
		RepositoryID: declaration.GenerationID, RepositoryClass: "critical-offsite", GenerationID: declaration.GenerationID, OffsiteRepositoryURL: declaration.RepositoryURL, PointID: declaration.SourcePointID, SourceID: "verified-critical-point", SourceRevision: declaration.StateRevision,
		RecoveryEpoch: binding.RecoveryEpoch, MaximumExpiresAt: maximum, MaximumObjects: declaration.MaximumPUTs, MaximumBytes: declaration.MaximumBytes, WriterLease: &lease}
	launcher := backup.CustodyLauncher{PolicyPath: runtimeConfig.config.CustodyPolicyPath, Writer: authority, Journal: authority, Clock: runtimeConfig.config.Clock}
	custody := &lazyCustody{launcher: launcher, session: session}
	verifierSession := session
	verifierSession.Role = "offsite-verifier"
	observer.launcher, observer.session = launcher, verifierSession
	cutoff := &qualifiedCutoff{clock: runtimeConfig.config.Clock, deadline: deadline}
	return backup.OffsiteRunSpec{PointID: declaration.SourcePointID,
		Policy: backup.OffsitePolicy{PolicyID: "offsite-" + declaration.GenerationID, ProfileID: "vegastack-labs", GenerationID: declaration.GenerationID, Bucket: runtimeConfig.config.Bucket, Prefix: runtimeConfig.config.Prefix,
			ParentReferenceID: runtimeConfig.config.ParentReferenceID, ParentFingerprint: runtimeConfig.config.ParentFingerprint, MaximumBytes: declaration.MaximumBytes, MaximumPUTs: declaration.MaximumPUTs, MaximumLISTs: declaration.MaximumLISTs,
			MaximumRetainedGenerations: declaration.MaximumRetainedGenerations, RuleLimit: declaration.RuleLimit, RetentionWindow: time.Duration(declaration.RetentionSeconds) * time.Second, SessionTTL: time.Duration(declaration.SessionTTLSeconds) * time.Second, Clock: runtimeConfig.config.Clock},
		Retention: retention, Copy: backup.CopyConfig{Custody: custody, Endpoint: endpoint, BinaryPath: runtimeConfig.config.ResticBinaryPath, Architecture: runtime.GOARCH, RepositoryURL: declaration.RepositoryURL, Bucket: runtimeConfig.config.Bucket, SnapshotPath: declaration.SnapshotPath,
			PasswordFDPath: "/proc/self/fd/3", AuthorizationTokenFDPath: "/proc/self/fd/4", IAMURI: writerIAMURI, Password: values[1], Inventory: observer, Binding: writerRequest},
		Verifier: backup.OffsiteVerifierConfig{Source: observer, ProofID: "proof-" + declaration.GenerationID, ProofClass: backup.OffsiteProofQualified, Clock: runtimeConfig.config.Clock, FullReadMaximumAge: 24 * time.Hour}, Cutoff: cutoff, WriterSealObservedAt: deadline}, nil
}

func serveOneRunEndpoint(issuer SessionIssuer, parent *credentialref.Value, request adapter.SessionRequest, bearer []byte, clock func() time.Time, afterClose func()) (*backup.OneRunEndpoint, string, error) {
	var server *http.Server
	var listener net.Listener
	endpoint, err := backup.NewOneRunEndpoint(backup.OneRunConfig{Issuer: issuer, Parent: parent, Request: request, Bearer: bearer, Path: backup.OneRunIAMPath(request), Clock: clock, OnClose: func() {
		if server != nil {
			_ = server.Shutdown(context.Background())
		}
		if listener != nil {
			_ = listener.Close()
		}
		if afterClose != nil {
			afterClose()
		}
	}})
	if err != nil {
		return nil, "", err
	}
	listener, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = endpoint.Close()
		return nil, "", err
	}
	server = &http.Server{Handler: endpoint, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = server.Serve(listener) }()
	return endpoint, "http://" + listener.Addr().String() + backup.OneRunIAMPath(request), nil
}

type custodyAuthority struct {
	repository    *store.OffsiteRepository
	stateRevision int64
	context       context.Context
}

func (authority *custodyAuthority) binding(session backup.CustodySession) store.OffsiteCustodyBinding {
	return store.OffsiteCustodyBinding{AttemptID: "custody-" + session.NonceDigest[7:], PlanID: session.PlanID, PlanDigest: session.PlanDigest, RunID: session.RunID, StepID: session.StepID, LeaseID: session.LeaseID, Role: session.Role, GenerationID: session.GenerationID, SourcePointID: session.PointID, StateRevision: authority.stateRevision, RecoveryEpoch: session.RecoveryEpoch, MaximumExpiresAt: session.MaximumExpiresAt, NonceDigest: session.NonceDigest}
}
func (authority *custodyAuthority) VerifyWriterLease(lease backup.WriterLease, now time.Time) error {
	return authority.repository.VerifyCustodyLease(authority.context, store.OffsiteCustodyBinding{PlanID: lease.PlanID, PlanDigest: lease.PlanDigest, RunID: lease.RunID, StepID: lease.StepID, LeaseID: lease.LeaseID, GenerationID: lease.TargetID, SourcePointID: lease.PointID, StateRevision: authority.stateRevision, RecoveryEpoch: lease.RecoveryEpoch, MaximumExpiresAt: lease.MaximumExpiresAt}, now)
}
func (authority *custodyAuthority) BeginCustody(ctx context.Context, session backup.CustodySession) error {
	return authority.repository.BeginCustody(ctx, authority.binding(session))
}
func (authority *custodyAuthority) FinishCustody(ctx context.Context, session backup.CustodySession, outcome string) error {
	return authority.repository.FinishCustody(ctx, authority.binding(session).AttemptID, outcome)
}

type lazyCustody struct {
	launcher backup.CustodyLauncher
	session  backup.CustodySession
}

func (custody *lazyCustody) RunOffsiteRestic(ctx context.Context, request backup.OffsiteResticRequest, password *credentialref.Value, bearer []byte) (backup.OffsiteResticResult, error) {
	client, err := custody.launcher.Start(ctx, custody.session)
	if err != nil {
		return backup.OffsiteResticResult{}, err
	}
	defer client.Close(context.WithoutCancel(ctx))
	result, err := client.RunOffsiteRestic(ctx, request, password, bearer)
	return result, err
}

type runObserver struct {
	s3                           S3Client
	credentials                  S3Credentials
	prefix                       string
	maximumObjects, maximumBytes int64
	fullReadAt                   time.Time
	clock                        func() time.Time
	launcher                     backup.CustodyLauncher
	session                      backup.CustodySession
	readEndpoint                 *backup.OneRunEndpoint
	readIAMURI                   string
	readBearer                   []byte
	password                     *credentialref.Value
	binaryPath, repositoryURL    string
	snapshotPath                 string
	last                         backup.OffsiteInventoryObservation
}

func (observer *runObserver) zero() {
	observer.credentials.AccessKeyID = ""
	observer.credentials.SecretAccessKey = ""
	observer.credentials.SessionToken = ""
	for index := range observer.readBearer {
		observer.readBearer[index] = 0
	}
	observer.readBearer = nil
}

func (observer *runObserver) ObserveOffsiteGeneration(ctx context.Context, _, _, _ string) (backup.OffsiteInventoryObservation, error) {
	value, err := observer.s3.Inventory(ctx, observer.prefix, observer.credentials, observer.maximumObjects, observer.maximumBytes)
	if err == nil {
		observer.last = value
	}
	return value, err
}
func (observer *runObserver) ObserveExpectedPoint(ctx context.Context, pending backup.PendingOffsiteGeneration) (backup.OffsiteGenerationObservation, error) {
	if observer.last.InventoryDigest == "" || observer.readEndpoint == nil || observer.password == nil {
		return backup.OffsiteGenerationObservation{}, errors.New("r2 full read unavailable")
	}
	request := backup.OffsiteResticRequest{BinaryPath: observer.binaryPath, Architecture: runtime.GOARCH, RepositoryURL: observer.repositoryURL, SnapshotPath: observer.snapshotPath,
		PasswordFDPath: "/proc/self/fd/3", IAMURI: observer.readIAMURI, AuthorizationTokenFDPath: "/proc/self/fd/4", RunID: observer.session.RunID, StepID: observer.session.StepID,
		PointID: observer.session.PointID, GenerationID: observer.session.GenerationID, RecoveryEpoch: observer.session.RecoveryEpoch, VerificationOnly: true}
	request.Arguments = []string{request.BinaryPath, "-r", request.RepositoryURL, "--json", "--no-cache", "--password-file", request.PasswordFDPath, "check", "--read-data"}
	request.Environment = []string{"HOME=/nonexistent", "RESTIC_PASSWORD_FILE=" + request.PasswordFDPath, "AWS_CONTAINER_CREDENTIALS_FULL_URI=" + request.IAMURI, "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE=" + request.AuthorizationTokenFDPath}
	client, err := observer.launcher.Start(ctx, observer.session)
	if err != nil {
		return backup.OffsiteGenerationObservation{}, err
	}
	result, verifyErr := client.RunOffsiteRestic(ctx, request, observer.password, observer.readBearer)
	closeErr := client.Close(context.WithoutCancel(ctx))
	observer.readEndpoint.MarkChildExited()
	if verifyErr != nil || closeErr != nil || !result.ChildExited || result.FullReadAt.IsZero() {
		return backup.OffsiteGenerationObservation{}, errors.New("r2 full read unavailable")
	}
	observer.fullReadAt = result.FullReadAt
	now := observer.clock().UTC()
	return backup.OffsiteGenerationObservation{GenerationID: pending.GenerationID, RepositoryID: pending.RepositoryID, InventoryDigest: observer.last.InventoryDigest, RuleDigest: pending.RuleDigest,
		SourcePointID: pending.SourcePointID, SourceSnapshotID: pending.SourceSnapshotID, SourceManifestDigest: pending.SourceManifestDigest, SourceInventoryDigest: pending.SourceInventoryDigest, SourceContentDigest: pending.SourceContentDigest,
		SourceDependencyDigest: pending.SourceDependencyDigest, SourceResticDigest: pending.SourceResticDigest, KeyReferenceID: pending.KeyReferenceID, SnapshotIDs: []string{pending.OffsiteSnapshotID}, ProtectedRules: pending.ProtectedRules, Objects: observer.last.Objects,
		ObjectCount: observer.last.ObjectCount, ObjectBytes: observer.last.ObjectBytes, MetadataValid: true, FullReadSucceeded: true, FullReadAt: observer.fullReadAt, ObservedAt: now}, nil
}

type qualifiedCutoff struct {
	clock    func() time.Time
	deadline time.Time
}

func (probe *qualifiedCutoff) AwaitWriterCutoff(ctx context.Context, pending backup.PendingOffsiteGeneration) (time.Time, error) {
	last := pending.SessionExpiries[0]
	for _, expiry := range pending.SessionExpiries[1:] {
		if expiry.After(last) {
			last = expiry
		}
	}
	if !last.Before(probe.deadline) && !last.Equal(probe.deadline) {
		return time.Time{}, errors.New("writer expiry exceeds plan deadline")
	}
	delay := last.Sub(probe.clock().UTC())
	if delay > 0 {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return time.Time{}, ctx.Err()
		case <-timer.C:
		}
	}
	return probe.clock().UTC(), nil
}
func (*qualifiedCutoff) DenyNewPUT(context.Context, string) (bool, error) { return true, nil }
func (*qualifiedCutoff) DenyMultipartCompletion(context.Context, string) (bool, error) {
	return true, nil
}

var _ backup.QualifiedOffsiteRuntime = (*ProductionRuntime)(nil)
