package qualification

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"testing"
	"time"
)

func TestNativeStepProfileUsesProtectedServiceOwner(t *testing.T) {
	scope := scopeFixture()
	now := time.Now().UTC().Truncate(time.Second)
	in := generated.NativeStepRequest{Schema: generated.SchemaIDNativeStepRequest, SchemaVersion: "1.0.0", ScopeDigest: hostaction.Digest(scope), GuestID: "subject", ScenarioID: "baseline-access", Ordinal: 1, ControllerInstanceID: scope.ControllerInstanceID, RecoveryEpoch: 0, Nonce: hostaction.Digest("nonce"), Deadline: now.Add(time.Minute).Format(time.RFC3339), Operation: "prepare"}
	uid, err := qualificationProfileOwner(scope, in, nativeClientProfilePath, 0, now)
	if err != nil || uid != uint32(scope.ControlServiceUID) || uid == 0 {
		t.Fatal("root witness did not select scoped nonroot profile owner", uid, err)
	}
	for _, kind := range []string{"foreign-path", "relative-path", "nonroot", "root-owner", "other-scope", "expired", "other-guest"} {
		t.Run(kind, func(t *testing.T) {
			s, r, path, caller := scope, in, nativeClientProfilePath, 0
			switch kind {
			case "foreign-path":
				path = "/etc/vsk-labs/control/server.json"
			case "relative-path":
				path = "/etc/vsk-labs/native/../native/client.json"
			case "nonroot":
				caller = int(scope.ControlServiceUID)
			case "root-owner":
				s.ControlServiceUID = 0
				r.ScopeDigest = hostaction.Digest(s)
			case "other-scope":
				r.ScopeDigest = hostaction.Digest("other")
			case "expired":
				r.Deadline = now.Format(time.RFC3339)
			case "other-guest":
				r.GuestID = "outside"
			}
			if _, e := qualificationProfileOwner(s, r, path, caller, now); e == nil {
				t.Fatal("foreign owner/path/scope accepted")
			}
		})
	}
	profile := serverconfig.Profile{SocketPath: "/run/vsk-labs/control.sock", SocketOwnerUID: uid}
	if validateQualificationClientProfile(profile, uid) != nil {
		t.Fatal("local service socket rejected")
	}
	for _, kind := range []string{"root-socket", "other-owner", "remote", "missing-socket"} {
		t.Run(kind, func(t *testing.T) {
			p := profile
			switch kind {
			case "root-socket":
				p.SocketOwnerUID = 0
			case "other-owner":
				p.SocketOwnerUID++
			case "remote":
				p.ConstrainedSSH = &serverconfig.ConstrainedSSH{}
			case "missing-socket":
				p.SocketPath = ""
			}
			if validateQualificationClientProfile(p, uid) == nil {
				t.Fatal("alternate socket authority accepted")
			}
		})
	}
}
