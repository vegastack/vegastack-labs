//go:build linux

package qualification

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"golang.org/x/sys/unix"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
)

const slackFixtureDirectory = "/run/vsk-labs-native"
const slackFixtureSetupPath = "/etc/vsk-labs/control/setup.json"

// RunSlackFixturePeer is a bounded, preparation-only Slack wire peer. It cannot
// access SQLite or acknowledgement services. The ordinary production adapter
// retains its fixed HTTPS/WSS endpoints and full certificate verification.
func RunSlackFixturePeer(ctx context.Context, sourceCommit string) error {
	if ctx == nil || os.Geteuid() != 0 || sourceCommit == "" || ownedDirectory(slackFixtureDirectory, 0) != nil {
		return ErrUnavailable
	}
	raw, err := ownedFile(slackFixtureDirectory+"/slack-fixture.json", 0, 32768)
	var scope generated.NativeSlackFixtureScope
	if err != nil || generated.ValidateContractJSON(generated.SchemaIDNativeSlackFixtureScope, raw, generated.ContractExact) != nil || json.Unmarshal(raw, &scope) != nil || scope.SourceCommit != sourceCommit {
		return ErrUnavailable
	}
	now := time.Now().UTC()
	issued, e := time.Parse(time.RFC3339, scope.IssuedAt)
	deadline, f := time.Parse(time.RFC3339, scope.ExpiresAt)
	if e != nil || f != nil || now.Before(issued) || !now.Before(deadline) || deadline.Sub(issued) > 4*time.Hour || !deadline.After(issued) {
		return ErrUnavailable
	}
	executable, err := fileDigest("/proc/self/exe", 256<<20)
	if err != nil || executable != scope.ExecutableDigest || verifyLocalGuest(generated.QualificationGuest{InstanceID: scope.GuestInstanceID, HostIdentityDigest: scope.HostIdentityDigest, SSHHostKeyDigest: scope.SSHHostKeyDigest}) != nil {
		return ErrUnavailable
	}
	machine, err := fixtureRootFile("/etc/machine-id", 128)
	if err != nil {
		return ErrUnavailable
	}
	identity := strings.TrimSpace(string(machine))
	if len(identity) != 32 || strings.Trim(identity, "0123456789abcdef") != "" || identity == strings.Repeat("0", 32) || hostaction.BytesDigest([]byte(identity)) != scope.SetupHostIdentityDigest {
		return ErrUnavailable
	}
	setupRaw, owner, mode, err := fixtureRegularFile(slackFixtureSetupPath, 32768)
	var setup generated.LocalSetupRequest
	if err != nil || generated.ValidateContractJSON(generated.SchemaIDLocalSetupRequest, setupRaw, generated.ContractExact) != nil || json.Unmarshal(setupRaw, &setup) != nil || owner == 0 || int64(owner) != setup.ServiceUID || mode != 0600 || setup.SetupID != scope.SetupPlanID || setup.HostIdentityDigest != scope.SetupHostIdentityDigest || hostaction.BytesDigest(setupRaw) != scope.SetupRequestDigest {
		return ErrUnavailable
	}
	setupExpiry, err := time.Parse(time.RFC3339, setup.ExpiresAt)
	if err != nil || !now.Before(setupExpiry) || setupExpiry.After(deadline) {
		return ErrUnavailable
	}
	app, err := ownedFile(slackFixtureDirectory+"/app-token", 0, 512)
	if err != nil {
		return ErrUnavailable
	}
	defer wipeFixture(app)
	bot, err := ownedFile(slackFixtureDirectory+"/bot-token", 0, 512)
	if err != nil {
		return ErrUnavailable
	}
	defer wipeFixture(bot)
	if !strings.HasPrefix(string(app), "xapp-native-fixture-") || !strings.HasPrefix(string(bot), "xoxb-native-fixture-") || len(app) < 40 || len(bot) < 40 || hostaction.BytesDigest(app) != scope.AppTokenDigest || hostaction.BytesDigest(bot) != scope.BotTokenDigest {
		return ErrUnavailable
	}
	cert, err := ownedFile(slackFixtureDirectory+"/server.crt", 0, 16384)
	if err != nil || hostaction.BytesDigest(cert) != scope.TLSCertificateDigest {
		return ErrUnavailable
	}
	key, err := ownedFile(slackFixtureDirectory+"/server.key", 0, 16384)
	if err != nil {
		return ErrUnavailable
	}
	defer wipeFixture(key)
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil || len(pair.Certificate) == 0 {
		return ErrUnavailable
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil || leaf.VerifyHostname("slack.com") != nil || leaf.VerifyHostname("wss-native.slack.com") != nil || now.Before(leaf.NotBefore) || deadline.After(leaf.NotAfter) {
		return ErrUnavailable
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	peer := &slackFixturePeer{scope: scope, setup: setup, appToken: app, botToken: bot, clock: time.Now, ctx: ctx, tickets: map[string]time.Time{}, used: map[string]bool{}, queue: make(chan []byte, 16)}
	peer.approvals = func() (generated.NativeSlackFixtureApprovalList, error) {
		var out generated.NativeSlackFixtureApprovalList
		raw, err := ownedFile(slackFixtureDirectory+"/approvals.json", 0, 65536)
		if err != nil || generated.ValidateContractJSON(generated.SchemaIDNativeSlackFixtureApprovalList, raw, generated.ContractExact) != nil || json.Unmarshal(raw, &out) != nil {
			return out, ErrUnavailable
		}
		return out, nil
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:443")
	if err != nil {
		return ErrUnavailable
	}
	defer listener.Close()
	server := &http.Server{Handler: peer, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}}}
	done := make(chan struct{})
	go func() { defer close(done); <-ctx.Done(); _ = server.Close() }()
	var setupDone chan error
	if scope.RunControlSetup {
		setupDone = make(chan error, 1)
		go func() {
			e := superviseFixtureControl(ctx, scope, setup)
			setupDone <- e
			if e != nil {
				cancel()
			}
		}()
	}
	err = server.Serve(tls.NewListener(listener, server.TLSConfig))
	cancel()
	<-done
	if setupDone != nil {
		if setupErr := <-setupDone; setupErr != nil {
			return ErrUnavailable
		}
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return ErrUnavailable
	}
	return nil
}
func wipeFixture(v []byte) {
	for i := range v {
		v[i] = 0
	}
}
func fixtureRegularFile(path string, limit int64) ([]byte, uint32, uint32, error) {
	fd, err := unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NONBLOCK, Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return nil, 0, 0, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Mode&0022 != 0 || st.Size > limit {
		return nil, 0, 0, ErrUnavailable
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return nil, 0, 0, ErrUnavailable
	}
	return raw, st.Uid, st.Mode & 0777, nil
}
func fixtureRootFile(path string, limit int64) ([]byte, error) {
	raw, uid, _, err := fixtureRegularFile(path, limit)
	if err != nil || uid != 0 {
		return nil, ErrUnavailable
	}
	return raw, nil
}
