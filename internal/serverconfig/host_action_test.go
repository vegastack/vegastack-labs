package serverconfig

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
	"strings"
	"testing"
)

func TestHostActionProfileRequiresExplicitProtectedIdentity(t *testing.T) {
	p := validGeneratedProfile()
	got, err := convertGeneratedProfile(p, 1001)
	if err != nil || got.HostActionSignerPath != "" || len(got.HostActionIdentityDigests) != 0 {
		t.Fatal("default action capability is enabled")
	}
	p.HostActionSignerPath = "/etc/vsk-labs/action.key"
	p.HostActionKeyID = "action-key"
	p.HostActionIdentityDigests = []string{"sha256:" + strings.Repeat("a", 64)}
	if _, err := convertGeneratedProfile(p, 1001); err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(*generated.ServerProfile){"missing key": func(p *generated.ServerProfile) { p.HostActionKeyID = "" }, "empty allowlist": func(p *generated.ServerProfile) { p.HostActionIdentityDigests = nil }, "relative key": func(p *generated.ServerProfile) { p.HostActionSignerPath = "action.key" }, "unknown identity": func(p *generated.ServerProfile) { p.HostActionIdentityDigests = []string{"host-alias"} }, "duplicate": func(p *generated.ServerProfile) {
		p.HostActionIdentityDigests = append(p.HostActionIdentityDigests, p.HostActionIdentityDigests[0])
	}, "hidden capability": func(p *generated.ServerProfile) { p.HostActionSignerPath = ""; p.HostActionKeyID = "" }} {
		t.Run(name, func(t *testing.T) {
			copy := p
			edit(&copy)
			if _, err := convertGeneratedProfile(copy, 1001); err == nil {
				t.Fatal("invalid action profile accepted")
			}
		})
	}
}
