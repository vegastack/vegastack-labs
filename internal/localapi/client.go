package localapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/result"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
)

const (
	maxResponseBodyBytes = 64 * 1024
	maxResponseHeaders   = 16 * 1024
	statusTimeout        = 3 * time.Second
)

var errRedirect = errors.New("redirect denied")

type Response struct {
	Raw      []byte
	Result   generated.RunResult
	Status   generated.ServerStatusData
	ExitCode int
}

type Client interface {
	Status(context.Context, serverconfig.Profile) (Response, error)
}

type client struct {
	results *result.Factory
}

func NewClient(results *result.Factory) Client {
	return &client{results: results}
}

func (client *client) Status(ctx context.Context, profile serverconfig.Profile) (Response, error) {
	if client.results == nil || profile.SocketPath == "" {
		return Response{}, responseFailure()
	}
	requestCtx, cancel := context.WithTimeout(ctx, statusTimeout)
	defer cancel()
	dialer := &net.Dialer{}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", profile.SocketPath)
		},
		DisableKeepAlives:      true,
		MaxResponseHeaderBytes: maxResponseHeaders,
	}
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   statusTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errRedirect
		},
	}
	request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, "http://local/api/v1/health", nil)
	if err != nil {
		return Response{}, responseFailure()
	}
	response, err := httpClient.Do(request)
	if err != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		if errors.Is(err, errRedirect) {
			return Response{}, responseFailure()
		}
		if ctx.Err() != nil {
			return Response{}, failure.New(generated.ErrorCodeInterrupted, "control-service", false)
		}
		var networkError *net.OpError
		if errors.As(err, &networkError) && (networkError.Op == "dial" || networkError.Timeout()) {
			return Response{}, failure.New(generated.ErrorCodeDependencyUnavailable, "control-service", true)
		}
		return Response{}, responseFailure()
	}
	defer response.Body.Close()
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return Response{}, responseFailure()
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBodyBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > maxResponseBodyBytes {
		return Response{}, responseFailure()
	}
	validated, err := validateStatusResponse(raw, response.StatusCode)
	if err != nil {
		return Response{}, err
	}
	return validated, nil
}

func validateStatusResponse(raw []byte, httpStatus int) (Response, error) {
	if len(raw) < 2 || raw[len(raw)-1] != '\n' {
		return Response{}, responseFailure()
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var envelope generated.RunResult
	if err := decoder.Decode(&envelope); err != nil {
		return Response{}, responseFailure()
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return Response{}, responseFailure()
	}
	canonical, err := json.Marshal(envelope)
	if err != nil || !bytes.Equal(raw, append(canonical, '\n')) {
		return Response{}, responseFailure()
	}
	if envelope.Schema != generated.SchemaIDRunResult || schemaMajor(envelope.SchemaVersion) != generated.SchemaMajor || envelope.Command != generated.CommandNameServerStatus ||
		envelope.RequestID == "" || envelope.ToolVersion == "" || envelope.ReleaseBuildID == "" || envelope.Changed || envelope.RunID != nil || envelope.SnapshotDigest != nil || envelope.PlanID != nil {
		return Response{}, responseFailure()
	}
	statusDecoder := json.NewDecoder(bytes.NewReader(envelope.Data))
	statusDecoder.DisallowUnknownFields()
	var status generated.ServerStatusData
	if err := statusDecoder.Decode(&status); err != nil {
		return Response{}, responseFailure()
	}
	if err := statusDecoder.Decode(&trailing); err != io.EOF || !validRemoteStatus(status, envelope) {
		return Response{}, responseFailure()
	}
	exitCode := 0
	if len(envelope.Errors) == 0 {
		if envelope.Status != generated.RunStatusSucceeded || httpStatus < 200 || httpStatus >= 300 {
			return Response{}, responseFailure()
		}
	} else {
		if httpStatus < 400 || envelope.Status == generated.RunStatusSucceeded {
			return Response{}, responseFailure()
		}
		for _, resultError := range envelope.Errors {
			if resultError.Target == "" {
				return Response{}, responseFailure()
			}
			if _, ok := generated.ErrorExitCodes[resultError.Code]; !ok {
				return Response{}, responseFailure()
			}
		}
		exitCode = generated.ErrorExitCodes[envelope.Errors[0].Code]
	}
	return Response{Raw: append([]byte(nil), raw...), Result: envelope, Status: status, ExitCode: exitCode}, nil
}

func validRemoteStatus(status generated.ServerStatusData, envelope generated.RunResult) bool {
	if status.RecoveryEpoch != envelope.RecoveryEpoch || status.StateRevision != envelope.StateRevision || status.MutationAvailable || status.State == "unavailable" {
		return false
	}
	switch status.State {
	case "ready", "safe-mode":
		return status.ReadAvailable
	case "starting", "stopping":
		return !status.ReadAvailable
	default:
		return false
	}
}

func schemaMajor(version string) int {
	major, _, ok := strings.Cut(version, ".")
	if !ok {
		return 0
	}
	value, err := strconv.Atoi(major)
	if err != nil {
		return 0
	}
	return value
}

func responseFailure() error {
	return failure.New(generated.ErrorCodeIntegrityFailure, "control-service-response", false)
}
