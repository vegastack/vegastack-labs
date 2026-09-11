package serverconfig

import (
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

func validGeneratedProfile() generated.ServerProfile {
	return generated.ServerProfile{
		Schema:               generated.SchemaIDServerProfile,
		SchemaVersion:        "1.1.0",
		SocketPath:           "/tmp/vsk-labs/control.sock",
		InventoryExportRoot:  "/tmp/vsk-labs/exports",
		SocketOwnerUID:       1001,
		SocketMode:           "0600",
		ShutdownGraceSeconds: 5,
		PrincipalBindings: []generated.LocalPrincipalBinding{
			{UID: 1001, PrincipalID: "principal.operator"},
		},
		RemoteRead: generated.RemoteReadProfile{Enabled: false},
	}
}

func stringPointer(value string) *string { return &value }

func enabledRemoteRead() generated.RemoteReadProfile {
	return generated.RemoteReadProfile{
		Enabled:            true,
		BindAddress:        stringPointer("127.0.0.1:8443"),
		PublicOrigin:       stringPointer("https://console.example"),
		TLSCertificatePath: stringPointer("/etc/vsk-labs/console.crt"),
		TLSPrivateKeyPath:  stringPointer("/etc/vsk-labs/console.key"),
		IdentityAdapter:    stringPointer("cloudflare-access"),
		IdentityConfigPath: stringPointer("/etc/vsk-labs/cloudflare-access.json"),
	}
}

func TestRemoteReadRequiresCompleteTLSAndIdentityConfiguration(t *testing.T) {
	profile := validGeneratedProfile()
	profile.RemoteRead = enabledRemoteRead()
	got, err := convertGeneratedProfile(profile, 1001)
	if err != nil {
		t.Fatal(err)
	}
	if !got.RemoteRead.Enabled || got.RemoteRead.ExactHost != "console.example" {
		t.Fatalf("remote read = %#v", got.RemoteRead)
	}

	for name, mutate := range map[string]func(*generated.RemoteReadProfile){
		"missing key": func(remote *generated.RemoteReadProfile) { remote.TLSPrivateKeyPath = nil },
		"plaintext origin": func(remote *generated.RemoteReadProfile) {
			remote.PublicOrigin = stringPointer("http://console.example")
		},
		"wildcard bind": func(remote *generated.RemoteReadProfile) { remote.BindAddress = stringPointer("0.0.0.0:8443") },
		"relative identity": func(remote *generated.RemoteReadProfile) {
			remote.IdentityConfigPath = stringPointer("cloudflare-access.json")
		},
		"unknown adapter": func(remote *generated.RemoteReadProfile) { remote.IdentityAdapter = stringPointer("provider-token") },
	} {
		t.Run(name, func(t *testing.T) {
			profile := validGeneratedProfile()
			profile.RemoteRead = enabledRemoteRead()
			mutate(&profile.RemoteRead)
			if _, err := convertGeneratedProfile(profile, 1001); err == nil {
				t.Fatal("partial or unsafe remote listener accepted")
			}
		})
	}
}

func TestDisabledRemoteReadRejectsHiddenConfiguration(t *testing.T) {
	profile := validGeneratedProfile()
	profile.RemoteRead.BindAddress = stringPointer("127.0.0.1:8443")
	if _, err := convertGeneratedProfile(profile, 1001); err == nil {
		t.Fatal("disabled remote listener accepted hidden configuration")
	}
}

func TestConvertGeneratedProfile(t *testing.T) {
	got, err := convertGeneratedProfile(validGeneratedProfile(), 1001)
	if err != nil {
		t.Fatal(err)
	}
	if got.SocketPath != "/tmp/vsk-labs/control.sock" || got.InventoryExportRoot != "/tmp/vsk-labs/exports" || got.SocketMode != 0o600 || got.ShutdownGrace.Seconds() != 5 || len(got.PrincipalBindings) != 1 {
		t.Fatalf("convertGeneratedProfile() = %#v", got)
	}
}

func TestConvertGeneratedProfileRejectsInvalidContracts(t *testing.T) {
	group := int64(2001)
	tests := map[string]func(*generated.ServerProfile){
		"schema":               func(p *generated.ServerProfile) { p.Schema = "wrong" },
		"version":              func(p *generated.ServerProfile) { p.SchemaVersion = "2.0.0" },
		"owner":                func(p *generated.ServerProfile) { p.SocketOwnerUID = 1002 },
		"relative socket":      func(p *generated.ServerProfile) { p.SocketPath = "relative.sock" },
		"unclean socket":       func(p *generated.ServerProfile) { p.SocketPath = "/tmp/../private.sock" },
		"nul socket":           func(p *generated.ServerProfile) { p.SocketPath = "/tmp/a\x00b" },
		"overlong socket":      func(p *generated.ServerProfile) { p.SocketPath = "/" + strings.Repeat("a", 107) },
		"relative export root": func(p *generated.ServerProfile) { p.InventoryExportRoot = "relative" },
		"unclean export root":  func(p *generated.ServerProfile) { p.InventoryExportRoot = "/tmp/../exports" },
		"root export root":     func(p *generated.ServerProfile) { p.InventoryExportRoot = "/" },
		"nul export root":      func(p *generated.ServerProfile) { p.InventoryExportRoot = "/tmp/a\x00b" },
		"overlong export root": func(p *generated.ServerProfile) { p.InventoryExportRoot = "/" + strings.Repeat("a", 4096) },
		"grace":                func(p *generated.ServerProfile) { p.ShutdownGraceSeconds = 4 },
		"mode":                 func(p *generated.ServerProfile) { p.SocketMode = "0640" },
		"group with 0600":      func(p *generated.ServerProfile) { p.SocketGroupGID = &group },
		"0660 without group":   func(p *generated.ServerProfile) { p.SocketMode = "0660" },
		"empty bindings":       func(p *generated.ServerProfile) { p.PrincipalBindings = nil },
		"duplicate uid": func(p *generated.ServerProfile) {
			p.PrincipalBindings = append(p.PrincipalBindings, generated.LocalPrincipalBinding{UID: 1001, PrincipalID: "principal.second"})
		},
		"duplicate principal": func(p *generated.ServerProfile) {
			p.PrincipalBindings = append(p.PrincipalBindings, generated.LocalPrincipalBinding{UID: 1002, PrincipalID: "principal.operator"})
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			profile := validGeneratedProfile()
			mutate(&profile)
			if _, err := convertGeneratedProfile(profile, 1001); err == nil {
				t.Fatal("conversion succeeded")
			} else if strings.Contains(err.Error(), profile.SocketPath) || strings.Contains(err.Error(), "principal.operator") {
				t.Fatalf("error leaked profile content: %v", err)
			}
		})
	}
}

func TestDecodeGeneratedProfileIsStrictAndBounded(t *testing.T) {
	valid := `{"schema":"vegastack-labs.dev/server-profile","schemaVersion":"1.1.0","socketPath":"/tmp/vsk-labs/control.sock","socketOwnerUid":1001,"socketGroupGid":null,"socketMode":"0600","shutdownGraceSeconds":5,"principalBindings":[{"uid":1001,"principalId":"principal.operator"}],"inventoryExportRoot":"/tmp/vsk-labs/exports","remoteRead":{"enabled":false,"bindAddress":null,"publicOrigin":null,"tlsCertificatePath":null,"tlsPrivateKeyPath":null,"identityAdapter":null,"identityConfigPath":null}}`
	for name, content := range map[string]string{
		"empty":          "",
		"unknown":        strings.Replace(valid, `"schema":`, `"unknown":true,"schema":`, 1),
		"multiple":       valid + valid,
		"oversized":      valid + strings.Repeat(" ", maxProfileBytes),
		"fractional uid": strings.Replace(valid, `"uid":1001`, `"uid":1.5`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeGeneratedProfile(strings.NewReader(content)); err == nil {
				t.Fatal("decode succeeded")
			}
		})
	}
	if _, err := decodeGeneratedProfile(strings.NewReader(valid)); err != nil {
		t.Fatalf("valid decode = %v", err)
	}
}
