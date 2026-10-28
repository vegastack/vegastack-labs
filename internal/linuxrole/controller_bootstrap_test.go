package linuxrole

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
)

func controllerInstallFixture() ControllerInstallInput {
	d := hostaction.BytesDigest([]byte("fixture"))
	return ControllerInstallInput{Stage: ControllerInstallStage, ControllerSetupPilotDigest: d, ControllerInstanceID: "synthetic-instance", ControllerMachineIDDigest: hostaction.BytesDigest([]byte(strings.Repeat("a", 32))), RecoveryImageDigest: d, StateRevision: 21, ServiceUID: 999, ServiceGID: 999, AdministratorUID: 1000, AdministratorGID: 1000, ExecutableDigest: d, ConfigDigest: d,
		Resources:               generated.LinuxRoleResources{Schema: generated.SchemaIDLinuxRoleResources, SchemaVersion: "1.0.0", MemoryMaxBytes: 1024, CPUQuotaPercent: 100, TasksMax: 128, MinimumFreeBytes: 1024, MinimumFreePercent: 5, CapacityMemoryBytes: 2048, CapacityCPUPercent: 200, CapacityTasks: 256},
		CredentialCustodyDigest: d, SlackProfileDigest: d, SlackCredentialNames: []string{"slack-app-token", "slack-bot-token", "slack-nonce-key"}, Preimages: map[string]string{"executable": d, "unit": "", "native-policy": "", "polkit": "", "sudoers": ""}, Probes: []ControllerNativeProbe{{CredentialName: "credential-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", UID: 999, GID: 999}, {CredentialName: "credential-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", UID: 1000, GID: 1000}}}
}

func TestControllerServiceConfigPreservesHumanAndProviderDeclarations(t *testing.T) {
	in := controllerInstallFixture()
	in.Stage = ControllerHandoffStage
	d := hostaction.BytesDigest([]byte("fixture"))
	in.Handoff = &ControllerServiceHandoff{ForegroundPID: 123, ForegroundStartIdentity: d, ForegroundExecutableDigest: d, WriterLockDigest: d, SocketIdentityDigest: d, CustodyDigest: d, DesiredConfigDigest: d, ExpiresAt: time.Now().Add(time.Minute).UTC().Format(time.RFC3339)}
	source := []byte(`{"socketOwnerUid":1000,"socketPath":"/run/vsk-labs-control/control.sock","socketMode":"0600","acknowledgementAdapterConfigPath":"/etc/vsk-labs/control/slack.json","inventoryExportRoot":"/var/lib/vsk-labs/control/exports","principalBindings":[{"uid":1000,"principalId":"operator-a"}],"remoteRead":{"enabled":false},"hostingLifecycleProfiles":[{"opaque":"preserve"}]}`)
	in.ConfigDigest = hostaction.BytesDigest(source)
	after, e := PrepareControllerServiceConfig(in, source)
	if e != nil {
		t.Fatal(e)
	}
	in.Handoff.DesiredConfigDigest = hostaction.BytesDigest(after)
	got, e := ControllerServiceConfig(in, source)
	if e != nil {
		t.Fatal(e)
	}
	var beforeFields, afterFields map[string]json.RawMessage
	json.Unmarshal(source, &beforeFields)
	json.Unmarshal(got, &afterFields)
	for key, value := range beforeFields {
		if key != "socketOwnerUid" && key != "socketMode" && string(afterFields[key]) != string(value) {
			t.Fatal("unrelated declaration changed", key)
		}
	}
	if string(afterFields["socketOwnerUid"]) != "999" || string(afterFields["socketGroupGid"]) != "1000" || string(afterFields["socketMode"]) != `"0660"` {
		t.Fatal("wrong finite socket migration")
	}
	if strings.Contains(string(afterFields["principalBindings"]), "999") {
		t.Fatal("service impersonates human")
	}
	in.Handoff.DesiredConfigDigest = d
	if _, e = ControllerServiceConfig(in, source); e == nil {
		t.Fatal("unbound resulting configuration accepted")
	}
	in.Handoff.ExpiresAt = "not-an-expiry"
	if ValidateControllerInstallInput(in) == nil {
		t.Fatal("unbounded handoff accepted")
	}
	in.Handoff = nil
	if ValidateControllerInstallInput(in) == nil {
		t.Fatal("missing handoff accepted")
	}
	in = controllerInstallFixture()
	in.Handoff = &ControllerServiceHandoff{}
	if ValidateControllerInstallInput(in) == nil {
		t.Fatal("handoff smuggled into foundation")
	}
}

func TestControllerFoundationUsesFixedRoleAndAuthorityRenderers(t *testing.T) {
	in := controllerInstallFixture()
	raw, _ := json.Marshal(in)
	got, e := DecodeControllerInstallInput(raw)
	if e != nil {
		t.Fatal(e)
	}
	files, e := ControllerFoundationFiles(got, strings.Repeat("a", 32))
	if e != nil {
		t.Fatal(e)
	}
	if len(files) != 4 {
		t.Fatal("unexpected artifact scope", len(files))
	}
	unit := string(files[controllerArtifacts["unit"]])
	for _, want := range []string{"User=999\n", "Group=999\n", "ExecStart=/usr/local/bin/vsk-labs server run --config /etc/vsk-labs/control/server.json\n", "Restart=no\n"} {
		if !strings.Contains(unit, want) {
			t.Fatal("missing fixed unit field", want)
		}
	}
	for _, forbidden := range []string{"LoadCredentialEncrypted", "backup/requests", "ExecStartPre", "/bin/sh"} {
		if strings.Contains(unit, forbidden) {
			t.Fatal("expanded initial unit", forbidden)
		}
	}
	var policy struct {
		Version int              `json:"version"`
		Machine string           `json:"machine_id"`
		Units   []string         `json:"units"`
		Probes  []map[string]any `json:"probes"`
	}
	if json.Unmarshal(files[controllerArtifacts["native-policy"]], &policy) != nil || policy.Version != 1 || len(policy.Units) != 1 || policy.Units[0] != "vsk-labs.service" || len(policy.Probes) != 2 {
		t.Fatal("native role policy incompatible")
	}
	if !strings.Contains(string(files[controllerArtifacts["polkit"]]), "action.lookup('verb') === 'restart'") {
		t.Fatal("restart confinement missing")
	}
	if strings.Contains(string(files[controllerArtifacts["sudoers"]]), "ALL\n") {
		t.Fatal("wildcard helper grant")
	}
}

func TestControllerFoundationRejectsExpandedOrUnboundInputs(t *testing.T) {
	for name, mutate := range map[string]func(*ControllerInstallInput){
		"unapproved-stage": func(i *ControllerInstallInput) { i.Stage = "install-anything" },
		"admin-is-service": func(i *ControllerInstallInput) { i.ServiceUID = i.AdministratorUID },
		"root-service":     func(i *ControllerInstallInput) { i.ServiceUID = 0 },
		"missing-preimage": func(i *ControllerInstallInput) { delete(i.Preimages, "unit") },
		"arbitrary-path":   func(i *ControllerInstallInput) { i.Preimages["/etc/passwd"] = "" },
		"unbound-policy":   func(i *ControllerInstallInput) { i.ControllerSetupPilotDigest = "" },
		"unbound-recovery": func(i *ControllerInstallInput) { i.RecoveryImageDigest = "" },
		"path-credential":  func(i *ControllerInstallInput) { i.Probes[0].CredentialName = "../secret" },
		"root-probe":       func(i *ControllerInstallInput) { i.Probes[0].UID = 0 },
		"duplicate-probe":  func(i *ControllerInstallInput) { i.Probes = append(i.Probes, i.Probes[0]) },
		"over-capacity":    func(i *ControllerInstallInput) { i.Resources.MemoryMaxBytes = 4096 },
	} {
		t.Run(name, func(t *testing.T) {
			in := controllerInstallFixture()
			mutate(&in)
			b, _ := json.Marshal(in)
			if _, e := DecodeControllerInstallInput(b); e == nil {
				t.Fatal("unsafe input accepted")
			}
		})
	}
	in := controllerInstallFixture()
	if _, e := ControllerFoundationFiles(in, strings.Repeat("b", 32)); e == nil {
		t.Fatal("wrong machine accepted")
	}
	b, _ := json.Marshal(in)
	b = append(b[:len(b)-1], []byte(`,"approved":true}`)...)
	if _, e := DecodeControllerInstallInput(b); e == nil {
		t.Fatal("caller approval accepted")
	}
	b = []byte(`{"stage":"foundation-native-authority","stage":"foundation-native-authority"}`)
	if _, e := DecodeControllerInstallInput(b); e == nil {
		t.Fatal("duplicate key accepted")
	}
}
