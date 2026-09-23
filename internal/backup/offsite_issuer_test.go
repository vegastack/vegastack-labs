package backup

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
)

type issuerFixture struct{ now time.Time }

func (issuer issuerFixture) Issue(context.Context, adapter.SessionRequest, *credentialref.Value) (adapter.ScopedS3Session, error) {
	return adapter.ScopedS3Session{AccessKeyID: []byte("access"), SecretAccessKey: []byte("session-secret"), SessionToken: []byte("session-token"), ExpiresAt: issuer.now.Add(time.Minute)}, nil
}

func testOneRunEndpoint(t *testing.T) (*OneRunEndpoint, adapter.SessionRequest, []byte) {
	t.Helper()
	now := time.Date(2026, 9, 23, 0, 0, 0, 0, time.UTC)
	parent, _ := credentialref.NewValue([]byte("parent-secret"))
	t.Cleanup(parent.Close)
	request := adapter.SessionRequest{RunID: "run-a", StepID: "step-a", PointID: "point-a", GenerationID: "generation-a", RecoveryEpoch: 7, Deadline: now.Add(5 * time.Minute), TTL: time.Minute, Prefix: "critical/generation-a/", Actions: []string{"DeleteObject", "GetObject", "ListBucket", "PutObject"}}
	bearer := []byte("0123456789abcdef0123456789abcdef")
	endpoint, err := NewOneRunEndpoint(OneRunConfig{Issuer: issuerFixture{now}, Parent: parent, Request: request, Bearer: bearer, Path: OneRunIAMPath(request), Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = endpoint.Close() })
	return endpoint, request, bearer
}

func TestOneRunEndpointRejectsWrongAndLateBearer(t *testing.T) {
	endpoint, request, bearer := testOneRunEndpoint(t)
	call := func(token string) int {
		req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1"+OneRunIAMPath(request), nil)
		req.RemoteAddr = "127.0.0.1:12345"
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		endpoint.ServeHTTP(rr, req)
		return rr.Code
	}
	if call("wrong") == http.StatusOK {
		t.Fatal("wrong bearer accepted")
	}
	if call(string(bearer)) != http.StatusOK {
		t.Fatal("valid bound bearer denied")
	}
	endpoint.MarkChildExited()
	if call(string(bearer)) == http.StatusOK {
		t.Fatal("late bearer accepted")
	}
}

type custodyFixture struct {
	endpoint *OneRunEndpoint
	bearer   []byte
	t        *testing.T
	point    VerifiedCriticalPoint
}

func (fixture custodyFixture) RunOffsiteRestic(_ context.Context, request OffsiteResticRequest, password *credentialref.Value, bearer []byte) (OffsiteResticResult, error) {
	if password == nil || string(password.Bytes()) != "repository-password" || string(bearer) != string(fixture.bearer) {
		fixture.t.Fatal("borrowed custody values mismatch")
	}
	joined := strings.Join(append(append([]string{}, request.Arguments...), request.Environment...), "\n")
	for _, secret := range []string{"parent-secret", "session-secret", "session-token", string(fixture.bearer)} {
		if strings.Contains(joined, secret) {
			fixture.t.Fatalf("secret leaked to child: %q", secret)
		}
	}
	if len(request.Environment) != 4 || strings.Contains(joined, "AWS_ACCESS_KEY_ID=") || strings.Contains(joined, "AWS_SECRET_ACCESS_KEY=") {
		fixture.t.Fatalf("unsafe environment: %#v", request.Environment)
	}
	req := httptest.NewRequest(http.MethodGet, request.IAMURI, nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("Authorization", "Bearer "+string(fixture.bearer))
	rr := httptest.NewRecorder()
	fixture.endpoint.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		fixture.t.Fatalf("iam status %d", rr.Code)
	}
	return OffsiteResticResult{RepositoryID: strings.Repeat("a", 64), SnapshotID: strings.Repeat("b", 64), ObjectCount: 8, ObjectBytes: 512, ChildExited: true}, nil
}

type inventoryFixture struct{}

func (inventoryFixture) ObserveOffsiteGeneration(context.Context, string, string, string) (OffsiteInventoryObservation, error) {
	objects := testOffsiteObjects(512)
	return OffsiteInventoryObservation{InventoryDigest: DigestOffsiteInventory(objects), ObjectCount: int64(len(objects)), ObjectBytes: 512, Objects: objects}, nil
}

func TestCopyOffsitePointUsesCustodyAndOneRunIAM(t *testing.T) {
	endpoint, binding, bearer := testOneRunEndpoint(t)
	now := time.Date(2026, 9, 23, 0, 0, 0, 0, time.UTC)
	point := testVerifiedCriticalPoint(now)
	admission := GenerationAdmission{GenerationID: "generation-a", Prefix: "critical/generation-a/", RuleDigest: offsiteDigest("f"), MaximumBytes: 1024, MaximumPUTs: 100, MaximumLISTs: 20,
		ProtectedRules: testProtectedRules(), MutablePrefixes: []string{"critical/generation-a/locks/"}}
	config := CopyConfig{Endpoint: endpoint, BinaryPath: "/opt/vsk/bin/restic-0.19.1", Architecture: "arm64", RepositoryURL: "s3:https://example.invalid/bucket/critical/generation-a", Bucket: "bucket", SnapshotPath: "/srv/vsk-exchange/point-a", PasswordFDPath: "/proc/self/fd/3", AuthorizationTokenFDPath: "/proc/self/fd/4", IAMURI: "http://127.0.0.1:54321" + OneRunIAMPath(binding), Binding: binding}
	password, _ := credentialref.NewValue([]byte("repository-password"))
	defer password.Close()
	config.Password = password
	config.Custody = custodyFixture{endpoint: endpoint, bearer: bearer, t: t, point: point}
	config.Inventory = inventoryFixture{}
	pending, err := CopyOffsitePoint(context.Background(), config, point, admission)
	if err != nil || pending.SourcePointID != point.PointID || pending.SourceSnapshotID == pending.OffsiteSnapshotID || len(pending.SessionExpiries) != 1 || pending.IssuanceStoppedAt.IsZero() {
		t.Fatalf("copy = %#v, %v", pending, err)
	}

	endpoint, binding, _ = testOneRunEndpoint(t)
	config.Endpoint, config.Binding = endpoint, binding
	config.RepositoryURL = "s3:https://example.invalid/bucket/unprotected/generation-a"
	config.IAMURI = "http://127.0.0.1:54321" + OneRunIAMPath(binding)
	if _, err := CopyOffsitePoint(context.Background(), config, point, admission); err == nil {
		t.Fatal("repository outside admitted protected prefix accepted")
	}
}
