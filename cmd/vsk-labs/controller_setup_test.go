package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/linuxrole"
)

func TestControllerSetupRequestHasNoCommandOrPathAuthority(t *testing.T) {
	d := hostaction.BytesDigest([]byte("synthetic"))
	in := linuxrole.ControllerInstallInput{Stage: linuxrole.ControllerInstallStage, ControllerSetupPilotDigest: d, ControllerInstanceID: "synthetic-instance", ControllerMachineIDDigest: d, RecoveryImageDigest: d, StateRevision: 21, ServiceUID: 999, ServiceGID: 999, AdministratorUID: 1000, AdministratorGID: 1000, ExecutableDigest: d, ConfigDigest: d, SlackProfileDigest: d, CredentialCustodyDigest: d,
		SlackCredentialNames: []string{"slack-app-token", "slack-bot-token", "slack-nonce-key"},
		Resources:            generated.LinuxRoleResources{Schema: generated.SchemaIDLinuxRoleResources, SchemaVersion: "1.0.0", MemoryMaxBytes: 1024, CPUQuotaPercent: 100, TasksMax: 128, MinimumFreeBytes: 1024, MinimumFreePercent: 5, CapacityMemoryBytes: 2048, CapacityCPUPercent: 200, CapacityTasks: 256},
		Preimages:            map[string]string{"executable": d, "unit": "", "native-policy": "", "polkit": "", "sudoers": ""},
		Probes:               []linuxrole.ControllerNativeProbe{{CredentialName: "credential-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", UID: 999, GID: 999}},
	}
	input, _ := json.Marshal(in)
	q := generated.ControllerSetupClaimRequest{Schema: generated.SchemaIDControllerSetupClaimRequest, SchemaVersion: "1.0.0", Reference: generated.PlanReferenceRequest{Schema: generated.SchemaIDPlanReferenceRequest, SchemaVersion: "1.0.0", PlanID: "plan-synthetic", PlanDigest: d, IdempotencyKey: "controller-setup-synthetic", Extensions: []generated.ContractExtension{}}, InputJSON: string(input)}
	raw, _ := json.Marshal(q)
	if _, _, e := decodeControllerSetupRequest(raw); e != nil {
		t.Fatal("closed request rejected", e)
	}
	for name, bad := range map[string][]byte{
		"command":   append(append([]byte{}, raw[:len(raw)-1]...), []byte(`,"command":"arbitrary"}`)...),
		"duplicate": append(append([]byte{}, raw[:len(raw)-1]...), []byte(`,"inputJson":"{}"}`)...),
		"oversized": []byte(strings.Repeat("x", controllerSetupMaximumInput+1)),
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, e := decodeControllerSetupRequest(bad); e == nil {
				t.Fatal("expanded request accepted")
			}
		})
	}
	q.InputJSON = " " + q.InputJSON
	raw, _ = json.Marshal(q)
	if _, _, e := decodeControllerSetupRequest(raw); e == nil {
		t.Fatal("noncanonical input accepted")
	}
}
