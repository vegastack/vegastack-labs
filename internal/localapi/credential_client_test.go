package localapi

import (
	"context"
	"io"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
)

type countedCredentialReader struct{ reads int }

func (reader *countedCredentialReader) Read(buffer []byte) (int, error) {
	reader.reads++
	return copy(buffer, []byte("synthetic-private-canary")), io.EOF
}

func TestCredentialImportRejectsRemoteTransportBeforePrivateRead(t *testing.T) {
	reader := &countedCredentialReader{}
	profile := serverconfig.Profile{ConstrainedSSH: &serverconfig.ConstrainedSSH{Executable: "ssh"}}
	input := generated.CredentialImportRequest{Schema: generated.SchemaIDCredentialImportRequest, SchemaVersion: "1.1.0", ReferenceID: "ref-a", ConsumerID: "consumer-a", PurposeID: "deploy-a", TargetID: "service-a", ResolverID: "native-systemd", MaterialVersion: "version-a", ExpectedStateRevision: 1, RecoveryEpoch: 0, TargetDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", IdempotencyKey: "import-a"}
	_, err := NewClient(clientTestFactory()).ImportCredential(context.Background(), profile, input, reader)
	stable, ok := failure.As(err)
	if !ok || stable.Code != generated.ErrorCodeAuthorizationDenied || reader.reads != 0 {
		t.Fatalf("remote import read=%d err=%v", reader.reads, err)
	}
}
