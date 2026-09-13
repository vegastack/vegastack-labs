// Package localtransport owns the one reviewed HTTP-over-Unix client used by
// the portable local API. Its public seam contains values only: callers cannot
// supply or recover an HTTP client, request, transport, URL, dialer, callback,
// connection, or other network-capable object.
package localtransport

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"path"
	"strings"
	"time"
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
	SocketPath    string
	Method        Method
	Path          string
	Body          []byte
	Timeout       time.Duration
	ResponseLimit int64
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
		request.Header.Set("Content-Type", "application/json")
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
	if input.SocketPath == "" || len(input.Path) == 0 || len(input.Path) > maximumPathBytes || strings.ContainsRune(input.Path, 0) ||
		!strings.HasPrefix(input.Path, "/api/v1/") || strings.ContainsAny(input.Path, "?#\\") || path.Clean(input.Path) != input.Path ||
		input.Timeout <= 0 || input.Timeout > maximumTimeout || input.ResponseLimit <= 0 || input.ResponseLimit > maximumResponseBytes || len(input.Body) > maximumRequestBytes {
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
