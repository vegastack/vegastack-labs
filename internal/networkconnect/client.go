package networkconnect

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"golang.org/x/crypto/ssh"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"
)

func Denied() error {
	return failure.New(generated.ErrorCodeAuthorizationDenied, "network-connect", false)
}
func unavailable() error {
	return failure.New(generated.ErrorCodeDependencyUnavailable, "network-connect", false)
}

type descriptorSource func(context.Context) (generated.NetworkConnectDescriptor, error)
type client struct {
	dial          func(context.Context, string, string) (net.Conn, error)
	timeout       time.Duration
	markerTimeout time.Duration
}

func Connect(ctx context.Context, path string, key []byte, fetch func(context.Context) (generated.NetworkConnectDescriptor, error)) (generated.NetworkConnectResult, error) {
	return client{dial: (&net.Dialer{Timeout: 5 * time.Second}).DialContext, timeout: 15 * time.Second, markerTimeout: 2 * time.Second}.connect(ctx, path, key, fetch)
}
func (c client) connect(ctx context.Context, path string, key []byte, fetch descriptorSource) (generated.NetworkConnectResult, error) {
	var out generated.NetworkConnectResult
	if path == "" {
		path = "auto"
	}
	if ctx == nil || fetch == nil || c.dial == nil || (path != "auto" && path != "lan" && path != "mesh") {
		return out, invalid()
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	before, err := fetch(ctx)
	if err != nil {
		return out, err
	}
	if ValidateEndpoint(before.Endpoint) != nil || before.GrantRevision < 1 || before.RecoveryEpoch != before.Endpoint.RecoveryEpoch {
		return out, Denied()
	}
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return out, invalid()
	}
	automatic := path == "auto"
	e := before.Endpoint
	if path == "auto" {
		path = "mesh"
		if c.marker(ctx, e) {
			path = "lan"
		}
	}
	address, port := e.MeshAddress, e.MeshPort
	if path == "lan" {
		address, port = e.LANAddress, e.LANPort
	}
	remote := net.JoinHostPort(address, strconv.FormatInt(port, 10))
	conn, err := c.dial(ctx, "tcp", remote)
	if err != nil && automatic && path == "lan" && ctx.Err() == nil {
		// No SSH protocol/authentication started when the LAN TCP dial failed.
		path = "mesh"
		remote = net.JoinHostPort(e.MeshAddress, strconv.FormatInt(e.MeshPort, 10))
		conn, err = c.dial(ctx, "tcp", remote)
	}
	if err != nil {
		return out, unavailable()
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	if err = conn.SetDeadline(deadline); err != nil {
		return out, unavailable()
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	hostkey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(e.HostKey))
	if err != nil {
		return out, invalid()
	}
	authenticated, _, _, err := ssh.NewClientConn(conn, remote, &ssh.ClientConfig{User: e.User, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: ssh.FixedHostKey(hostkey), Timeout: c.timeout})
	if err != nil {
		return out, unavailable()
	}
	// No SSH client/session or request dispatcher is created. Closing this
	// authenticated transport is the entire remote effect of this diagnostic.
	if err = authenticated.Close(); err != nil {
		return out, unavailable()
	}
	if ctx.Err() != nil {
		return out, failure.New(generated.ErrorCodeInterrupted, "network-connect", false)
	}
	after, err := fetch(ctx)
	if err != nil {
		return out, err
	}
	if ctx.Err() != nil {
		return out, failure.New(generated.ErrorCodeInterrupted, "network-connect", false)
	}
	if before.EndpointDigest != after.EndpointDigest || before.Endpoint.HostID != after.Endpoint.HostID || before.Endpoint.HostIdentityDigest != after.Endpoint.HostIdentityDigest || before.Endpoint != after.Endpoint || before.StateRevision != after.StateRevision || before.RecoveryEpoch != after.RecoveryEpoch || before.GrantRevision != after.GrantRevision {
		return out, Denied()
	}
	return generated.NetworkConnectResult{Schema: generated.SchemaIDNetworkConnectResult, SchemaVersion: "1.0.0", HostID: e.HostID, Path: path, EndpointDigest: before.EndpointDigest, Outcome: "authenticated-and-closed"}, nil
}
func (c client) marker(ctx context.Context, e generated.NetworkEndpoint) bool {
	ctx, cancel := context.WithTimeout(ctx, c.markerTimeout)
	defer cancel()
	transport := &http.Transport{Proxy: nil, DialContext: c.dial, ForceAttemptHTTP2: false, DisableKeepAlives: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true, VerifyConnection: func(cs tls.ConnectionState) error {
		// The exact declared leaf certificate is the trust anchor; no ambient CA,
		// DNS assertion or provider token supplies trust for this private marker.
		if len(cs.PeerCertificates) == 0 {
			return Denied()
		}
		cert := cs.PeerCertificates[0]
		sum := sha256.Sum256(cert.Raw)
		now := time.Now()
		if "sha256:"+hex.EncodeToString(sum[:]) != e.MarkerCertificateDigest || now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
			return Denied()
		}
		return nil
	}}}
	defer transport.CloseIdleConnections()
	httpClient := http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+net.JoinHostPort(e.MarkerAddress, strconv.FormatInt(e.MarkerPort, 10))+e.MarkerPath, nil)
	if err != nil {
		return false
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 129))
	return err == nil && string(raw) == e.MarkerValue
}
