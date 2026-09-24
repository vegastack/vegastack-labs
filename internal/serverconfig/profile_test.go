package serverconfig

import (
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

func validGeneratedProfile() generated.ServerProfile {
	return generated.ServerProfile{
		Schema:               generated.SchemaIDServerProfile,
		SchemaVersion:        "1.3.0",
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
	if !got.RemoteRead.Enabled || !got.RemoteRead.ConfigurationValid || got.RemoteRead.ExactHost != "console.example" {
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
			got, err := convertGeneratedProfile(profile, 1001)
			if err != nil || !got.RemoteRead.Enabled || got.RemoteRead.ConfigurationValid {
				t.Fatalf("unsafe remote configuration was not isolated: %#v, %v", got.RemoteRead, err)
			}
		})
	}
}

func TestDisabledRemoteReadRejectsHiddenConfiguration(t *testing.T) {
	profile := validGeneratedProfile()
	profile.RemoteRead.BindAddress = stringPointer("127.0.0.1:8443")
	got, err := convertGeneratedProfile(profile, 1001)
	if err != nil || !got.RemoteRead.Enabled || got.RemoteRead.ConfigurationValid {
		t.Fatalf("hidden remote configuration was not isolated: %#v, %v", got.RemoteRead, err)
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

func TestConvertGeneratedProfileRequiresCompleteLocalBackup(t *testing.T) {
	// Absent custody group disables local backup.
	got, err := convertGeneratedProfile(validGeneratedProfile(), 1001)
	if err != nil || got.LocalBackup != nil {
		t.Fatalf("absent local backup = %#v, %v", got.LocalBackup, err)
	}

	// Partial configuration fails closed.
	partial := validGeneratedProfile()
	partial.StandardBackupRoot = stringPointer("/srv/vsk-backup-standard")
	if _, err := convertGeneratedProfile(partial, 1001); err == nil {
		t.Fatal("partial local backup accepted")
	}

	// Complete custody group with distinct clean absolute paths converts.
	complete := validGeneratedProfile()
	complete.StandardBackupRoot = stringPointer("/srv/vsk-backup-standard")
	complete.CriticalBackupRoot = stringPointer("/srv/vsk-backup-critical")
	complete.ResticBinaryPath = stringPointer("/opt/vsk/bin/restic-0.19.1")
	complete.CustodyPolicyPath = stringPointer("/etc/vsk-labs/backup-custody.json")
	got, err = convertGeneratedProfile(complete, 1001)
	if err != nil || got.LocalBackup == nil ||
		got.LocalBackup.StandardRoot != "/srv/vsk-backup-standard" ||
		got.LocalBackup.CriticalRoot != "/srv/vsk-backup-critical" ||
		got.LocalBackup.ResticBinaryPath != "/opt/vsk/bin/restic-0.19.1" ||
		got.LocalBackup.CustodyPolicyPath != "/etc/vsk-labs/backup-custody.json" ||
		got.LocalBackup.StandardRoot == got.LocalBackup.CriticalRoot {
		t.Fatalf("complete local backup = %#v, %v", got.LocalBackup, err)
	}

	// Structural rejections: relative, unclean, root, and duplicate roots.
	for name, mutate := range map[string]func(*generated.ServerProfile){
		"relative root":  func(p *generated.ServerProfile) { p.StandardBackupRoot = stringPointer("relative/backup") },
		"unclean root":   func(p *generated.ServerProfile) { p.CriticalBackupRoot = stringPointer("/srv/../critical") },
		"root path":      func(p *generated.ServerProfile) { p.ResticBinaryPath = stringPointer("/") },
		"duplicate root": func(p *generated.ServerProfile) { p.CriticalBackupRoot = stringPointer("/srv/vsk-backup-standard") },
	} {
		t.Run(name, func(t *testing.T) {
			profile := validGeneratedProfile()
			profile.StandardBackupRoot = stringPointer("/srv/vsk-backup-standard")
			profile.CriticalBackupRoot = stringPointer("/srv/vsk-backup-critical")
			profile.ResticBinaryPath = stringPointer("/opt/vsk/bin/restic-0.19.1")
			profile.CustodyPolicyPath = stringPointer("/etc/vsk-labs/backup-custody.json")
			mutate(&profile)
			if _, err := convertGeneratedProfile(profile, 1001); err == nil {
				t.Fatal("invalid local backup accepted")
			}
		})
	}
}

func TestConvertGeneratedProfileRequiresCompleteOffsiteBackupAndLocalCustody(t *testing.T) {
	base := validGeneratedProfile()
	account, bucket, prefix := strings.Repeat("a", 32), "labs-backup", "critical"
	endpoint := "https://" + account + ".r2.cloudflarestorage.com"
	base.OffsiteEndpoint = &endpoint
	if _, err := convertGeneratedProfile(base, uint32(base.SocketOwnerUID)); err == nil {
		t.Fatal("partial offsite profile accepted")
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	reference := "reference-r2-parent"
	observer := "reference-r2-observer"
	lockAdmin, retention := "reference-r2-lock-admin", "reference-r2-retention"
	base.OffsiteBucket = &bucket
	base.OffsitePrefix = &prefix
	base.OffsiteParentReferenceID = &reference
	base.OffsiteObserverReferenceID = &observer
	base.OffsiteLockAdminReferenceID, base.OffsiteLockAdminFingerprint = &lockAdmin, &digest
	base.OffsiteRetentionReferenceID, base.OffsiteRetentionFingerprint = &retention, &digest
	base.OffsiteParentFingerprint = &digest
	base.OffsiteRuleDigest = &digest
	base.OffsiteG008EvidenceDigest = &digest
	base.OffsiteAccountID = &account
	base.OffsiteQualificationDigest = &digest
	base.OffsitePutCutoffDigest = &digest
	base.OffsiteMultipartCutoffDigest = &digest
	availableBytes, availablePUTs, availableLISTs, ruleCount, retained := int64(1<<30), int64(1000), int64(100), int64(5), int64(1)
	base.OffsiteAvailableBytes, base.OffsiteAvailablePUTs, base.OffsiteAvailableLISTs = &availableBytes, &availablePUTs, &availableLISTs
	base.OffsiteRuleCount, base.OffsiteRetainedGenerations = &ruleCount, &retained
	if _, err := convertGeneratedProfile(base, uint32(base.SocketOwnerUID)); err == nil {
		t.Fatal("offsite profile without local custody accepted")
	}
	standard, critical, binary, custody := "/srv/standard", "/srv/critical", "/opt/vsk/restic", "/etc/vsk/custody.json"
	base.StandardBackupRoot = &standard
	base.CriticalBackupRoot = &critical
	base.ResticBinaryPath = &binary
	base.CustodyPolicyPath = &custody
	profile, err := convertGeneratedProfile(base, uint32(base.SocketOwnerUID))
	if err != nil || profile.OffsiteBackup == nil || profile.OffsiteBackup.ParentReferenceID != reference {
		t.Fatalf("complete profile = %#v, %v", profile.OffsiteBackup, err)
	}
}

func TestAcknowledgementAdapterConfigPathIsOptionalAndAbsolute(t *testing.T) {
	profile := validGeneratedProfile()
	profile.AcknowledgementAdapterConfigPath = "/etc/vsk-labs/slack-acknowledgement.json"
	got, err := convertGeneratedProfile(profile, 1001)
	if err != nil || got.AcknowledgementAdapterConfigPath != profile.AcknowledgementAdapterConfigPath {
		t.Fatalf("slack config = %#v, %v", got, err)
	}
	profile.AcknowledgementAdapterConfigPath = "relative.json"
	if _, err := convertGeneratedProfile(profile, 1001); err == nil {
		t.Fatal("relative Slack config path accepted")
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
	valid := `{"schema":"vegastack-labs.dev/server-profile","schemaVersion":"1.3.0","socketPath":"/tmp/vsk-labs/control.sock","socketOwnerUid":1001,"socketGroupGid":null,"socketMode":"0600","shutdownGraceSeconds":5,"principalBindings":[{"uid":1001,"principalId":"principal.operator"}],"inventoryExportRoot":"/tmp/vsk-labs/exports","remoteRead":{"enabled":false,"bindAddress":null,"publicOrigin":null,"tlsCertificatePath":null,"tlsPrivateKeyPath":null,"identityAdapter":null,"identityConfigPath":null}}`
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
