//go:build linux

package qualification

import (
	"context"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/debianaccess"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/hostdiscovery"
	"github.com/vegastack/vegastack-labs/internal/hostreplacement"
	"golang.org/x/crypto/ssh"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

func ObserveNativeFail2ban(ctx context.Context) (NativeFail2banState, error) {
	var out NativeFail2banState
	if os.Geteuid() != 0 {
		return out, ErrUnavailable
	}
	command := func(args ...string) ([]byte, error) {
		bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		cmd := exec.CommandContext(bounded, "/usr/bin/fail2ban-client", args...)
		cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
		cmd.Stderr = io.Discard
		pipe, e := cmd.StdoutPipe()
		if e != nil {
			return nil, e
		}
		if cmd.Start() != nil {
			return nil, ErrUnavailable
		}
		raw, e := io.ReadAll(io.LimitReader(pipe, 16385))
		if len(raw) > 16384 {
			cmd.Process.Kill()
		}
		wait := cmd.Wait()
		if e != nil || wait != nil || len(raw) > 16384 {
			return nil, ErrUnavailable
		}
		return raw, nil
	}
	raw, err := command("status", "sshd")
	if err != nil {
		return out, err
	}
	out, err = parseFail2banStatus(raw)
	if err != nil {
		return out, err
	}
	for name, dest := range map[string]*int64{"maxretry": &out.MaxRetry, "findtime": &out.FindTimeSeconds, "bantime": &out.BanTimeSeconds} {
		raw, e := command("get", "sshd", name)
		if e != nil {
			return out, e
		}
		*dest, e = strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
		if e != nil {
			return out, ErrUnavailable
		}
	}
	out.ObservedAt = time.Now().UTC().Format(time.RFC3339Nano)
	return out, nil
}
func ObserveNativeSSHFailures(ctx context.Context, scope generated.QualificationScope, in NativeFail2banInput) (NativeSSHObservation, error) {
	return observeNativeSSH(ctx, scope, in, false)
}
func ObserveNativeSSHAdmin(ctx context.Context, scope generated.QualificationScope, in NativeFail2banInput) (NativeSSHObservation, error) {
	return observeNativeSSH(ctx, scope, in, true)
}
func observeNativeSSH(ctx context.Context, scope generated.QualificationScope, in NativeFail2banInput, admin bool) (NativeSSHObservation, error) {
	out := NativeSSHObservation{Outcomes: []string{}}
	s, err := validateScope(scope)
	if err != nil || !scopeCurrent(s, time.Now().UTC()) || os.Geteuid() != 0 || hostdiscovery.ValidateTarget(in.Target) != nil || in.Source.Kind != "host-network" || in.Target.Address != in.Destination.Address || in.Target.Port != in.Destination.Port || in.Destination.Port != 22 || in.Source.HostID == in.Destination.HostID {
		return out, ErrUnavailable
	}
	for schema, value := range map[string]any{generated.SchemaIDAccessProbeSource: in.Source, generated.SchemaIDAccessProbeTuple: in.Destination} {
		raw, _ := json.Marshal(value)
		if generated.ValidateContractJSON(schema, raw, generated.ContractExact) != nil {
			return out, ErrUnavailable
		}
	}
	keyDigest, e := hostreplacement.SSHHostKeyDigest(in.Target.HostKey)
	if e != nil {
		return out, e
	}
	sourceOK, targetOK := false, false
	for _, guest := range s.guests {
		if guest.HostID == in.Source.HostID && guest.HostIdentityDigest == in.Source.IdentityDigest {
			sourceOK = true
		}
		if guest.HostID == in.Destination.HostID && guest.HostIdentityDigest == in.Destination.IdentityDigest && guest.SSHHostKeyDigest == keyDigest {
			targetOK = true
		}
	}
	if !sourceOK || !targetOK {
		return out, ErrUnavailable
	}
	out.SourceHostID = in.Source.HostID
	out.SourceIdentityDigest = in.Source.IdentityDigest
	out.DestinationHostID = in.Destination.HostID
	out.DestinationIdentityDigest = in.Destination.IdentityDigest
	out.DestinationAddress = in.Destination.Address
	out.DestinationPort = in.Destination.Port
	out.User = in.Target.User
	out.InputDigest = hostaction.Digest(generated.NativeFail2banInput{Schema: generated.SchemaIDNativeFail2banInput, SchemaVersion: "1.0.0", Target: in.Target, Source: in.Source, Destination: in.Destination})
	var key []byte
	kind, count := "ssh-invalid-key", 5
	if admin {
		kind, count = "ssh-key", 1
		key, e = ownedFile("/etc/vsk-labs/native/admin.key", 0, 16384)
		if e != nil {
			return out, e
		}
		defer func() {
			for i := range key {
				key[i] = 0
			}
		}()
		signer, e := ssh.ParsePrivateKey(key)
		if e == nil {
			out.PublicKeyDigest = hostaction.BytesDigest(signer.PublicKey().Marshal())
		}
		if e != nil || in.Target.CredentialPublicKeyDigest == nil || hostaction.BytesDigest(signer.PublicKey().Marshal()) != *in.Target.CredentialPublicKeyDigest {
			return out, ErrUnavailable
		}
	}
	err = debianaccess.NewNativeSourceResolver().WithSource(ctx, in.Source, []generated.AccessProbeTuple{in.Destination}, func(identity debianaccess.SourceIdentity) error {
		out.NamespaceDigest = identity.NamespaceDigest
		out.RouteDigest = identity.RouteDigest
		out.SourceAddress = in.Source.Address
		out.HostKeyVerified = true
		for i := 0; i < count; i++ {
			observed := debianaccess.ProbeSocket(ctx, debianaccess.SocketProbe{Timeout: 2 * time.Second, SourceIP: in.Source.Address, DestinationIP: in.Destination.Address, Port: 22, HostKey: in.Target.HostKey, User: in.Target.User, Kind: kind}, key)
			if observed.LocalIP != in.Source.Address || !observed.PinnedKey || observed.Outcome == "error" {
				return ErrUnavailable
			}
			out.HostKeyVerified = out.HostKeyVerified && observed.PinnedKey
			out.Outcomes = append(out.Outcomes, observed.Outcome)
		}
		return nil
	})
	out.ObservedAt = time.Now().UTC().Format(time.RFC3339Nano)
	return out, err
}
