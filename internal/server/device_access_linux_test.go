//go:build linux

package server

import (
	"context"
	"database/sql"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"os"
	"path/filepath"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/store"
)

// The transport claim is synthetic and server-supplied. Real HTTP keep-alive
// and SQLite prove that an already authenticated connection is checked again.
func TestDeviceAccessRevocationOnExistingConnection(t *testing.T) {
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(dir, "control.db")
	authority, e := store.Open(context.Background(), store.Config{DatabasePath: path, Mode: store.InitializeNew, ExpectedUID: uint32(os.Getuid()), ToolVersion: "test", BuildVersion: "test"})
	if e != nil {
		t.Fatal(e)
	}
	defer authority.Close()
	db, e := sql.Open("sqlite3", path)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	exec := func(q string) {
		t.Helper()
		if _, e := db.Exec(q); e != nil {
			t.Fatal(e)
		}
	}
	exec(`INSERT INTO effective_authorization_principals VALUES('human-device','human','active',1,'now','now')`)
	exec(`INSERT INTO read_principals VALUES('human-device','active',1,'now','now')`)
	exec(`INSERT INTO operator_devices VALUES('device-synthetic','human-device','pending',1,'now','now')`)
	s := &service{config: Config{Application: &testApplication{}, Results: testResultFactory(), DeviceAuthorizer: store.NewEffectiveAuthorizationRepository(authority)}}
	resolver, e := identity.NewLocalPrincipalResolver([]identity.Binding{{UID: uint32(os.Getuid()), PrincipalID: "human-device", DeviceID: "device-synthetic"}})
	if e != nil {
		t.Fatal(e)
	}
	p, e := resolver.ResolveLocalPeer(context.Background(), identity.LocalPeer{UID: uint32(os.Getuid())})
	if e != nil {
		t.Fatal(e)
	}
	httpServer := httptest.NewUnstartedServer(s)
	httpServer.Config.ConnContext = func(ctx context.Context, _ net.Conn) context.Context { return identity.WithVerifiedPrincipal(ctx, p) }
	httpServer.Start()
	defer httpServer.Close()
	client := httpServer.Client()
	transport := client.Transport.(*http.Transport)
	transport.MaxConnsPerHost = 1
	requestNumber := 0
	request := func(want int) {
		t.Helper()
		var reused bool
		req, e := http.NewRequest(http.MethodGet, httpServer.URL+"/api/v1/synthetic", nil)
		if e != nil {
			t.Fatal(e)
		}
		req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{GotConn: func(i httptrace.GotConnInfo) { reused = i.Reused }}))
		resp, e := client.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != want {
			t.Fatalf("request %d status %d want %d", requestNumber, resp.StatusCode, want)
		}
		if requestNumber > 0 && !reused {
			t.Fatal("test lost existing connection")
		}
		requestNumber++
	}
	request(403)
	exec(`UPDATE operator_devices SET status='approved',device_revision=2 WHERE device_id='device-synthetic'`)
	request(404)
	exec(`UPDATE effective_authorization_principals SET status='suspended' WHERE principal_id='human-device'`)
	request(403)
	exec(`UPDATE effective_authorization_principals SET status='active' WHERE principal_id='human-device'`)
	request(404)
	exec(`UPDATE operator_devices SET status='revoked',device_revision=3 WHERE device_id='device-synthetic'`)
	request(403)
	exec(`UPDATE effective_authorization_principals SET status='revoked' WHERE principal_id='human-device'`)
	request(403)
}
