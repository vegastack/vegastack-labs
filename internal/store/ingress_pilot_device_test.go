package store

import (
	"database/sql"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
)

// Real SQL on the three tables the ingress device checks read; nothing else.
func ingressPilotFixture(t *testing.T) (*sql.DB, discoveryRow) {
	t.Helper()
	db, err := sql.Open(sqliteDriverName, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	for _, q := range []string{
		`CREATE TABLE effective_authorization_principals (principal_id TEXT, status TEXT, grant_revision INTEGER)`,
		`CREATE TABLE effective_authorization_grants (principal_id TEXT, grant_revision INTEGER, status TEXT, action TEXT, capability TEXT, resource_kind TEXT, resource_id TEXT, role_id TEXT)`,
		`CREATE TABLE operator_devices (device_id TEXT, principal_id TEXT, status TEXT)`,
		`INSERT INTO effective_authorization_principals VALUES ('omkar-mohanta','active',1),('other-admin','active',1),('suspended-admin','suspended',1)`,
		`INSERT INTO effective_authorization_grants VALUES
			('omkar-mohanta',1,'active','author','network.ingress.prepare','ingress-profile','labs','control-plane-admin'),
			('other-admin',1,'active','author','network.ingress.prepare','ingress-profile','labs','control-plane-admin'),
			('suspended-admin',1,'active','author','network.ingress.prepare','ingress-profile','labs','control-plane-admin')`,
	} {
		if _, err = db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	return db, func(q string, a ...any) *sql.Row { return db.QueryRow(q, a...) }
}

func ingressErrorCode(err error) string {
	if err == nil {
		return ""
	}
	return strings.SplitN(err.Error(), ":", 2)[0]
}

func TestIngressGrantPilotExceptionIsExactlyThePinnedLocalAdministrator(t *testing.T) {
	_, row := ingressPilotFixture(t)
	pilot := &IngressControllerPilot{PrincipalID: "omkar-mohanta", DeviceID: "controller-pilot"}
	local := func(id, device string) identity.Principal {
		return identity.Principal{ID: id, Method: identity.LocalOSPeerMethod, DeviceID: device}
	}
	for _, test := range []struct {
		name  string
		repo  *IngressRepository
		actor identity.Principal
		want  string
	}{
		{"pinned local administrator without a device", (&IngressRepository{}).WithControllerPilot(pilot), local("omkar-mohanta", ""), ""},
		{"no pilot configured keeps the device requirement", &IngressRepository{}, local("omkar-mohanta", ""), generated.ErrorCodeAuthenticationRequired},
		{"nil repository keeps the device requirement", nil, local("omkar-mohanta", ""), generated.ErrorCodeAuthenticationRequired},
		{"another principal is not exempt", (&IngressRepository{}).WithControllerPilot(pilot), local("other-admin", ""), generated.ErrorCodeAuthenticationRequired},
		{"pinned principal over a non-local method is not exempt", (&IngressRepository{}).WithControllerPilot(pilot), identity.Principal{ID: "omkar-mohanta", Method: identity.CloudflareAccessMethod, Kind: identity.PrincipalHuman}, generated.ErrorCodeAuthenticationRequired},
		{"pinned principal with an unapproved device id is not exempt", (&IngressRepository{}).WithControllerPilot(pilot), local("omkar-mohanta", "made-up-device"), generated.ErrorCodeAuthorizationDenied},
		{"exemption does not bypass the grant itself", (&IngressRepository{}).WithControllerPilot(&IngressControllerPilot{PrincipalID: "unprivileged", DeviceID: "controller-pilot"}), local("unprivileged", ""), generated.ErrorCodeAuthorizationDenied},
		{"exemption does not revive a suspended principal", (&IngressRepository{}).WithControllerPilot(&IngressControllerPilot{PrincipalID: "suspended-admin", DeviceID: "controller-pilot"}), local("suspended-admin", ""), generated.ErrorCodeAuthorizationDenied},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := test.repo.grant(identity.WithVerifiedPrincipal(t.Context(), test.actor), row, "labs", "author")
			if got := ingressErrorCode(err); got != test.want {
				t.Fatalf("error %q (%v) want %q", got, err, test.want)
			}
		})
	}
}

func TestIngressGrantOrdinaryApprovedDeviceStillWorks(t *testing.T) {
	db, row := ingressPilotFixture(t)
	repo := &IngressRepository{}
	actor := identity.Principal{ID: "other-admin", Method: identity.LocalOSPeerMethod, DeviceID: "device-1"}
	ctx := identity.WithVerifiedPrincipal(t.Context(), actor)
	if _, err := repo.grant(ctx, row, "labs", "author"); ingressErrorCode(err) != generated.ErrorCodeAuthorizationDenied {
		t.Fatalf("unapproved device: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO operator_devices VALUES ('device-1','other-admin','approved')`); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.grant(ctx, row, "labs", "author"); err != nil {
		t.Fatalf("approved device: %v", err)
	}
}

func TestIngressOwnerPilotExceptionRequiresTheExactPinnedPair(t *testing.T) {
	_, row := ingressPilotFixture(t)
	repo := (&IngressRepository{}).WithControllerPilot(&IngressControllerPilot{PrincipalID: "omkar-mohanta", DeviceID: "controller-pilot"})
	change := func(owner, device string) generated.IngressChange {
		return generated.IngressChange{OwnerID: owner, DeviceID: device}
	}
	for _, test := range []struct {
		name string
		repo *IngressRepository
		c    generated.IngressChange
		want string
	}{
		{"pinned pair without a device row", repo, change("omkar-mohanta", "controller-pilot"), ""},
		{"different device id", repo, change("omkar-mohanta", "other-device"), generated.ErrorCodeAuthorizationDenied},
		{"different owner", repo, change("other-admin", "controller-pilot"), generated.ErrorCodeAuthorizationDenied},
		{"inactive pinned owner", (&IngressRepository{}).WithControllerPilot(&IngressControllerPilot{PrincipalID: "suspended-admin", DeviceID: "controller-pilot"}), change("suspended-admin", "controller-pilot"), generated.ErrorCodeAuthorizationDenied},
		{"no pilot configured", &IngressRepository{}, change("omkar-mohanta", "controller-pilot"), generated.ErrorCodeAuthorizationDenied},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := ingressErrorCode(test.repo.owner(row, test.c)); got != test.want {
				t.Fatalf("error %q want %q", got, test.want)
			}
		})
	}
}

func TestWithControllerPilotIgnoresIncompletePins(t *testing.T) {
	for _, p := range []*IngressControllerPilot{nil, {PrincipalID: "omkar-mohanta"}, {DeviceID: "controller-pilot"}} {
		if r := (&IngressRepository{}).WithControllerPilot(p); r.pilot != nil {
			t.Fatalf("incomplete pin %+v enabled the exception", p)
		}
	}
}
