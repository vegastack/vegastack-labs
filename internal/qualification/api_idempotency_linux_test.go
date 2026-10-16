//go:build linux

package qualification

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/localapi"
	"github.com/vegastack/vegastack-labs/internal/result"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
)

func TestNativeAPIPlanEncodesIdentifierSafeNonceKey(t *testing.T) {
	for _, lead := range []string{"0", "9", "a", "f"} {
		t.Run(lead, func(t *testing.T) {
			step := generated.NativeStepRequest{Nonce: "sha256:" + lead + strings.Repeat("0", 63)}
			factory := result.NewFactory(result.BuildInfo{ToolVersion: "test", ReleaseBuildID: "test"}, func() (string, error) { return nativeAPIRequestID(step), nil })
			directory, err := os.MkdirTemp("/tmp", "vsk-plan-id-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(directory) })
			path := filepath.Join(directory, "api.sock")
			listener, err := net.Listen("unix", path)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.Chmod(path, 0600); err != nil {
				t.Fatal(err)
			}
			type observed struct {
				request generated.PlanCreateRequest
				valid   bool
			}
			captured := make(chan observed, 1)
			server := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/plan-preparation") {
					data := generated.PlanPreparation{Schema: generated.SchemaIDPlanPreparation, SchemaVersion: "1.0.0", DeclarationID: "gate-profile-native-profile", DeclarationRevision: 1, ExpectedStateRevision: 3, RecoveryEpoch: 0, ObservationFingerprint: hostaction.Digest("actual-test-observation")}
					envelope, e := factory.Success("api.v1.declarations.plan-preparation.get", 0, 3, data)
					if e != nil {
						w.WriteHeader(500)
						return
					}
					_ = json.NewEncoder(w).Encode(envelope)
					return
				}
				raw, e := io.ReadAll(io.LimitReader(r.Body, 32769))
				var input generated.PlanCreateRequest
				valid := e == nil && r.Method == http.MethodPost && r.URL.Path == "/api/v1/declarations/gate-profile-native-profile/plans" && json.Unmarshal(raw, &input) == nil && generated.ValidateContractJSON(generated.SchemaIDPlanCreateRequest, raw, generated.ContractExact) == nil
				captured <- observed{input, valid}
				// Stop after the real client encoding and server contract validation;
				// no plan execution or artificial successful plan is needed.
				envelope, e := factory.Failure("api.v1.plans.create", generated.RunStatusFailed, generated.ErrorCodeInputInvalid, "test-stop-after-validation", false, 0, 3, struct{}{})
				if e != nil {
					w.WriteHeader(500)
					return
				}
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(envelope)
			})}
			go func() { _ = server.Serve(listener) }()
			t.Cleanup(func() { _ = server.Close() })
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, err = localapi.NewClient(factory).Plan(ctx, serverconfig.Profile{SocketPath: path, SocketOwnerUID: uint32(os.Getuid())}, "gate-profile-native-profile", 1)
			if err != nil {
				t.Fatal("real plan client failed before encoded request", err)
			}
			select {
			case got := <-captured:
				if !got.valid {
					t.Fatal("native nonce generated an invalid PlanCreateRequest idempotency key")
				}
				if got.request.IdempotencyKey != "native-"+strings.TrimPrefix(step.Nonce, "sha256:") {
					t.Fatal("nonce bits or deterministic prefix lost")
				}
			default:
				t.Fatal("client did not send plan request")
			}
		})
	}
}

type nativeApplyKeyClient struct {
	localapi.Client
	captured *generated.PlanReferenceRequest
}

func (c nativeApplyKeyClient) ApplyBound(_ context.Context, _ serverconfig.Profile, in generated.PlanReferenceRequest) (localapi.TypedResponse[generated.RunPresentation], error) {
	*c.captured = in
	return localapi.TypedResponse[generated.RunPresentation]{}, errors.New("stop-before-apply")
}
func TestNativeAPIExecuteUsesSameIdentifierSafeKey(t *testing.T) {
	step := generated.NativeStepRequest{Nonce: "sha256:" + strings.Repeat("0", 64)}
	var captured generated.PlanReferenceRequest
	_, _ = dispatchNativeAPI(context.Background(), nativeAPIPacket{Kind: "execute", Step: step}, nativeApplyKeyClient{captured: &captured}, serverconfig.Profile{})
	if captured.IdempotencyKey != "native-"+strings.TrimPrefix(step.Nonce, "sha256:") {
		t.Fatal("execute uses unprefixed or different nonce binding")
	}
}
