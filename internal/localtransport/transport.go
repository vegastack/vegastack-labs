// Package localtransport owns the one reviewed HTTP-over-Unix client used by
// the portable local API. Its public seam contains values only: callers cannot
// supply or recover an HTTP client, request, transport, URL, dialer, callback,
// connection, or other network-capable object.
package localtransport

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
)

type Method = string

const (
	MethodGet  = "GET"
	MethodPost = "POST"

	StatusOK                 = 200
	StatusBadRequest         = 400
	StatusUnauthorized       = 401
	StatusForbidden          = 403
	StatusNotFound           = 404
	StatusConflict           = 409
	StatusPreconditionFailed = 412
	StatusRequestTimeout     = 408
	StatusBadGateway         = 502
	StatusServiceUnavailable = 503

	maximumPathBytes       = 4096
	maximumRequestBytes    = 8 << 20
	maximumResponseBytes   = 24 << 20
	maximumResponseHeaders = 16 * 1024
	maximumTimeout         = 30 * time.Second
)

var (
	ErrInvalid     = errors.New("invalid local transport request")
	ErrRedirect    = errors.New("local transport redirect denied")
	ErrUnavailable = errors.New("local transport unavailable")
)

type Request struct {
	SocketPath         string
	Method             Method
	Path               string
	Body               []byte
	BinaryCredential   bool
	CredentialMetadata []byte
	Timeout            time.Duration
	ResponseLimit      int64
}

type Response struct {
	StatusCode  int
	ContentType string
	Body        []byte
}

func RoundTrip(ctx context.Context, input Request) (Response, error) {
	if !validRequest(input) {
		return Response{}, ErrInvalid
	}
	requestCtx, cancel := context.WithTimeout(ctx, input.Timeout)
	defer cancel()
	dialer := &net.Dialer{}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", input.SocketPath)
		},
		DisableKeepAlives:      true,
		MaxResponseHeaderBytes: maximumResponseHeaders,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		Timeout:   input.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return ErrRedirect
		},
	}
	request, err := http.NewRequestWithContext(requestCtx, input.Method, "http://local"+input.Path, bytes.NewReader(input.Body))
	if err != nil {
		return Response{}, ErrInvalid
	}
	if input.Method == MethodPost {
		if input.BinaryCredential {
			request.Header.Set("Content-Type", "application/octet-stream")
			request.Header.Set("X-Vsk-Credential-Request", base64.RawURLEncoding.EncodeToString(input.CredentialMetadata))
		} else {
			request.Header.Set("Content-Type", "application/json")
		}
	}
	response, err := client.Do(request)
	if err != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		if errors.Is(err, ErrRedirect) {
			return Response{}, ErrRedirect
		}
		return Response{}, ErrUnavailable
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, input.ResponseLimit+1))
	if err != nil || len(body) == 0 || int64(len(body)) > input.ResponseLimit {
		return Response{}, ErrInvalid
	}
	return Response{StatusCode: response.StatusCode, ContentType: response.Header.Get("Content-Type"), Body: body}, nil
}

func validRequest(input Request) bool {
	requestPath, query, hasQuery := strings.Cut(input.Path, "?")
	if input.SocketPath == "" || len(input.Path) == 0 || len(input.Path) > maximumPathBytes || strings.ContainsRune(input.Path, 0) ||
		!strings.HasPrefix(requestPath, "/api/v1/") || strings.ContainsAny(input.Path, "#\\") || path.Clean(requestPath) != requestPath ||
		(hasQuery && !validCIEnrollmentQuery(input.Method, requestPath, query)) ||
		input.Timeout <= 0 || input.Timeout > maximumTimeout || input.ResponseLimit <= 0 || input.ResponseLimit > maximumResponseBytes || len(input.Body) > maximumRequestBytes {
		return false
	}
	if input.BinaryCredential {
		if input.Method != MethodPost || len(input.Body) < 8 || len(input.Body) > 4096 || len(input.CredentialMetadata) == 0 || len(input.CredentialMetadata) > 4096 || !credentialImportPath(input.Path) {
			return false
		}
	} else if len(input.CredentialMetadata) != 0 {
		return false
	}
	switch input.Method {
	case MethodGet:
		return len(input.Body) == 0
	case MethodPost:
		return len(input.Body) > 0
	default:
		return false
	}
}

// Only the existing CI list endpoint may carry canonical, bounded pagination.
// Other paths retain the transport's query prohibition.
func validCIEnrollmentQuery(method, requestPath, query string) bool {
	if method != MethodGet || requestPath != "/api/v1/ci/enrollments" {
		return false
	}
	values, err := url.ParseQuery(query)
	if err != nil || values.Encode() != query || len(values["limit"]) != 1 {
		return false
	}
	for key, list := range values {
		if len(list) != 1 {
			return false
		}
		value := list[0]
		switch key {
		case "limit":
			n, err := strconv.Atoi(value)
			if err != nil || n < 1 || n > 100 || strconv.Itoa(n) != value {
				return false
			}
		case "after":
			if len(value) == 0 || len(value) > 128 || value[0] < 'a' || value[0] > 'z' {
				return false
			}
			for _, c := range value {
				if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.ContainsRune("._:-", c)) {
					return false
				}
			}
		default:
			return false
		}
	}
	return true
}

func credentialImportPath(requestPath string) bool {
	const prefix, suffix = "/api/v1/credential-references/", "/import-stream"
	if !strings.HasPrefix(requestPath, prefix) || !strings.HasSuffix(requestPath, suffix) {
		return false
	}
	id := strings.TrimSuffix(strings.TrimPrefix(requestPath, prefix), suffix)
	_, err := credentialref.ParseID(id)
	return err == nil
}
