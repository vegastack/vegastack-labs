package hostaction

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

func TestMalformedEnvelopeDenialIsBoundedAndDoesNotEchoInput(t *testing.T) {
	var output bytes.Buffer
	err := RunOnce(context.Background(), strings.NewReader("{\"untrustedSecret\":\"do-not-echo\"}\n"), &output, Policy{}, &Receipts{}, ProductionDispatcher(), time.Now, rand.Reader)
	if err == nil {
		t.Fatal("malformed envelope accepted")
	}
	raw := bytes.TrimSpace(output.Bytes())
	if len(raw) > MaximumFrame || bytes.Contains(raw, []byte("do-not-echo")) || generated.ValidateContractJSON(generated.SchemaIDHostActionDenial, raw, generated.ContractExact) != nil {
		t.Fatalf("invalid sanitized denial %q", raw)
	}
	var denied generated.HostActionDenial
	if json.Unmarshal(raw, &denied) != nil || denied.Phase != "envelope" || denied.Code != generated.ErrorCodeAuthorizationDenied || denied.BundleDigest != "" || denied.ExecutionDigest != "" {
		t.Fatal("misleading denial phase")
	}
}
