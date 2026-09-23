package r2

import (
	"context"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
)

type signerFixture struct{ parentSeen bool }

func (s *signerFixture) SignScopedSession(_ context.Context, parent []byte, request adapter.SessionRequest) (adapter.ScopedS3Session, error) {
	s.parentSeen = string(parent) == "parent-secret"
	return adapter.ScopedS3Session{AccessKeyID: []byte("access"), SecretAccessKey: []byte("secret"), SessionToken: []byte("token"), ExpiresAt: request.Deadline.Add(-time.Minute)}, nil
}

func TestSessionIssuerBindsParentAndExactScope(t *testing.T) {
	now := time.Date(2026, 9, 23, 0, 0, 0, 0, time.UTC)
	signer := &signerFixture{}
	parent, _ := credentialref.NewValue([]byte("parent-secret"))
	defer parent.Close()
	issuer := SessionIssuer{Signer: signer, Clock: func() time.Time { return now }, ParentReferenceID: "reference-a", ParentFingerprint: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	request := adapter.SessionRequest{ParentReferenceID: issuer.ParentReferenceID, ParentFingerprint: issuer.ParentFingerprint, RunID: "run-a", StepID: "step-a", PointID: "point-a", GenerationID: "generation-a", Prefix: "critical/generation-a/", Actions: []string{"PutObject", "ListBucket", "GetObject", "DeleteObject"}, RecoveryEpoch: 7, Deadline: now.Add(10 * time.Minute), TTL: 9 * time.Minute}
	if _, err := issuer.Issue(context.Background(), request, parent); err != nil || !signer.parentSeen {
		t.Fatalf("issue = %v parent=%v", err, signer.parentSeen)
	}
	request.Actions = []string{"PutObject", "ListBucket", "GetObject"}
	if _, err := issuer.Issue(context.Background(), request, parent); err == nil {
		t.Fatal("session without lock cleanup authority accepted")
	}
	request.Actions = []string{"PutObject", "ListBucket", "GetObject", "DeleteObject", "PutBucketObjectLockConfiguration"}
	if _, err := issuer.Issue(context.Background(), request, parent); err == nil {
		t.Fatal("session with rule administration authority accepted")
	}
	request.Actions = []string{"PutObject", "ListBucket", "GetObject", "DeleteObject"}
	request.Prefix = ""
	if _, err := issuer.Issue(context.Background(), request, parent); err == nil {
		t.Fatal("unbound prefix accepted")
	}
}
