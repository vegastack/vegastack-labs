package r2

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
)

type signerFixture struct {
	parentSeen bool
	err        error
	issued     adapter.ScopedS3Session
}

func (s *signerFixture) SignScopedSession(_ context.Context, parent []byte, request adapter.SessionRequest) (adapter.ScopedS3Session, error) {
	s.parentSeen = string(parent) == "parent-secret"
	s.issued = adapter.ScopedS3Session{AccessKeyID: []byte("access"), SecretAccessKey: []byte("secret"), SessionToken: []byte("token"), ExpiresAt: request.Deadline.Add(-time.Minute)}
	return s.issued, s.err
}

func TestSessionIssuerZeroesPartialCredentialsOnSignerError(t *testing.T) {
	now := time.Date(2026, 9, 23, 0, 0, 0, 0, time.UTC)
	signer := &signerFixture{err: errors.New("signing failed")}
	parent, _ := credentialref.NewValue([]byte("parent-secret"))
	defer parent.Close()
	issuer := SessionIssuer{Signer: signer, Clock: func() time.Time { return now }, ParentReferenceID: "reference-a", ParentFingerprint: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	request := adapter.SessionRequest{ParentReferenceID: issuer.ParentReferenceID, ParentFingerprint: issuer.ParentFingerprint, RunID: "run-a", StepID: "step-a", PointID: "point-a", GenerationID: "generation-a", Prefix: "critical/generation-a/", Actions: append([]string(nil), allowedWriterActions...), RecoveryEpoch: 7, Deadline: now.Add(10 * time.Minute), TTL: 9 * time.Minute}
	if _, err := issuer.Issue(context.Background(), request, parent); err == nil {
		t.Fatal("signer error accepted")
	}
	for _, value := range [][]byte{signer.issued.AccessKeyID, signer.issued.SecretAccessKey, signer.issued.SessionToken} {
		for _, item := range value {
			if item != 0 {
				t.Fatal("partial session credential retained after signer error")
			}
		}
	}
}

func TestSessionIssuerBindsParentAndExactScope(t *testing.T) {
	now := time.Date(2026, 9, 23, 0, 0, 0, 0, time.UTC)
	signer := &signerFixture{}
	parent, _ := credentialref.NewValue([]byte("parent-secret"))
	defer parent.Close()
	issuer := SessionIssuer{Signer: signer, Clock: func() time.Time { return now }, ParentReferenceID: "reference-a", ParentFingerprint: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	request := adapter.SessionRequest{ParentReferenceID: issuer.ParentReferenceID, ParentFingerprint: issuer.ParentFingerprint, RunID: "run-a", StepID: "step-a", PointID: "point-a", GenerationID: "generation-a", Prefix: "critical/generation-a/", Actions: append([]string(nil), allowedWriterActions...), RecoveryEpoch: 7, Deadline: now.Add(10 * time.Minute), TTL: 9 * time.Minute}
	if _, err := issuer.Issue(context.Background(), request, parent); err != nil || !signer.parentSeen {
		t.Fatalf("issue = %v parent=%v", err, signer.parentSeen)
	}
	request.Actions = []string{"PutObject", "ListObjectsV2", "GetObject"}
	if _, err := issuer.Issue(context.Background(), request, parent); err == nil {
		t.Fatal("session without lock cleanup authority accepted")
	}
	request.Actions = []string{"PutObject", "ListObjectsV2", "GetObject", "DeleteObject", "PutBucketObjectLockConfiguration"}
	if _, err := issuer.Issue(context.Background(), request, parent); err == nil {
		t.Fatal("session with rule administration authority accepted")
	}
	request.Actions = append([]string(nil), allowedWriterActions...)
	request.Prefix = ""
	if _, err := issuer.Issue(context.Background(), request, parent); err == nil {
		t.Fatal("unbound prefix accepted")
	}
}
