package linuxrole

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/strictjson"
)

const ControllerInstallStage = "foundation-native-authority"
const ControllerRecoveryImage = "/var/lib/vsk-labs/control/controller-pilot-recovery.db"

// ControllerInstallInput is the closed, non-secret payload of the initial local
// administrator effect. It does not grant permission to execute that effect.
type ControllerInstallInput struct {
	Stage                      string                       `json:"stage"`
	ControllerSetupPilotDigest string                       `json:"controllerSetupPilotDigest"`
	ControllerInstanceID       string                       `json:"controllerInstanceId"`
	ControllerMachineIDDigest  string                       `json:"controllerMachineIdDigest"`
	RecoveryEpoch              int64                        `json:"recoveryEpoch"`
	StateRevision              int64                        `json:"stateRevision"`
	RecoveryImageDigest        string                       `json:"recoveryImageDigest"`
	ServiceUID                 int64                        `json:"serviceUid"`
	ServiceGID                 int64                        `json:"serviceGid"`
	AdministratorUID           int64                        `json:"administratorUid"`
	AdministratorGID           int64                        `json:"administratorGid"`
	ExecutableDigest           string                       `json:"executableDigest"`
	ConfigDigest               string                       `json:"configDigest"`
	SlackProfileDigest         string                       `json:"slackProfileDigest"`
	SlackCredentialNames       []string                     `json:"slackCredentialNames"`
	Resources                  generated.LinuxRoleResources `json:"resources"`
	Probes                     []ControllerNativeProbe      `json:"probes"`
	Preimages                  map[string]string            `json:"preimages"`
}

type ControllerNativeProbe struct {
	CredentialName string `json:"credentialName"`
	UID            int64  `json:"uid"`
	GID            int64  `json:"gid"`
}

var controllerDigest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var controllerArtifacts = map[string]string{
	"executable":    "usr/local/bin/vsk-labs",
	"unit":          "etc/systemd/system/vsk-labs.service",
	"native-policy": "etc/vsk-labs/native-credential-authority.json",
	"polkit":        "etc/polkit-1/rules.d/00-vsk-native-credential-restart.rules",
	"sudoers":       "etc/sudoers.d/49-vsk-native-credential-probe",
}

func DecodeControllerInstallInput(raw []byte) (ControllerInstallInput, error) {
	var in ControllerInstallInput
	if len(raw) == 0 || len(raw) > MaximumInput || strictjson.Scan(context.Background(), raw, strictjson.Limits{MaxDepth: 16}) != nil {
		return in, errInput
	}
	d := json.NewDecoder(strings.NewReader(string(raw)))
	d.DisallowUnknownFields()
	if d.Decode(&in) != nil || ValidateControllerInstallInput(in) != nil {
		return in, errInput
	}
	return in, nil
}

func ValidateControllerInstallInput(in ControllerInstallInput) error {
	if in.Stage != ControllerInstallStage || in.ControllerInstanceID == "" || len(in.ControllerInstanceID) > 128 || in.RecoveryEpoch < 0 || in.StateRevision < 0 || in.ServiceUID < 1 || in.ServiceGID < 1 || in.AdministratorUID < 1 || in.AdministratorGID < 1 || in.ServiceUID == in.AdministratorUID || in.ServiceUID > 0x7fffffff || in.ServiceGID > 0x7fffffff || in.AdministratorUID > 0x7fffffff || in.AdministratorGID > 0x7fffffff {
		return errInput
	}
	for _, d := range []string{in.ControllerSetupPilotDigest, in.ControllerMachineIDDigest, in.RecoveryImageDigest, in.ExecutableDigest, in.ConfigDigest, in.SlackProfileDigest} {
		if !controllerDigest.MatchString(d) {
			return errInput
		}
	}
	if len(in.Preimages) != len(controllerArtifacts) {
		return errInput
	}
	for selector := range controllerArtifacts {
		d, ok := in.Preimages[selector]
		if !ok || d != "" && !controllerDigest.MatchString(d) {
			return errInput
		}
	}
	b, e := json.Marshal(in.Resources)
	if e != nil || generated.ValidateContractJSON(generated.SchemaIDLinuxRoleResources, b, generated.ContractExact) != nil {
		return errInput
	}
	r := in.Resources
	if r.MemoryMaxBytes > r.CapacityMemoryBytes || r.CPUQuotaPercent > r.CapacityCPUPercent || r.TasksMax > r.CapacityTasks || r.MinimumFreePercent > 100 {
		return errInput
	}
	if len(in.Probes) < 1 || len(in.Probes) > 256 {
		return errInput
	}
	if len(in.SlackCredentialNames) != 3 {
		return errInput
	}
	lastName := ""
	for _, name := range in.SlackCredentialNames {
		if !controlCredentialName.MatchString(name) || strings.Contains(name, "..") || name <= lastName {
			return errInput
		}
		lastName = name
	}
	last := ""
	for _, p := range in.Probes {
		key := fmt.Sprintf("%s\x00%010d\x00%010d", p.CredentialName, p.UID, p.GID)
		if !controlCredentialName.MatchString(p.CredentialName) || strings.Contains(p.CredentialName, "..") || p.UID < 1 || p.GID < 1 || p.UID > 0x7fffffff || p.GID > 0x7fffffff || key <= last {
			return errInput
		}
		last = key
	}
	return nil
}

// ControllerFoundationFiles reuses the canonical role service renderer. The
// machine ID is observed locally, never accepted as an authority claim.
func ControllerFoundationFiles(in ControllerInstallInput, machineID string) (map[string][]byte, error) {
	if ValidateControllerInstallInput(in) != nil || !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(machineID) || hostaction.BytesDigest([]byte(machineID)) != in.ControllerMachineIDDigest {
		return nil, errInput
	}
	files := DesiredFiles(generated.LinuxRoleInput{RoleID: "control", Accounts: []generated.LinuxRoleAccount{{Selector: "control", UID: in.ServiceUID, GID: in.ServiceGID}}, Resources: in.Resources, ControlPlainCredentials: in.SlackCredentialNames})
	unit := controllerArtifacts["unit"]
	files[unit] = []byte(strings.Replace(string(files[unit]), "RuntimeDirectoryMode=0700\n", fmt.Sprintf("RuntimeDirectoryMode=0750\nSupplementaryGroups=%d\n", in.AdministratorGID), 1))
	// The finite installed sudo policy/access probes need privilege elevation,
	// as in the ordinary role renderer when native encrypted refs are present.
	files[unit] = []byte(strings.Replace(string(files[unit]), "NoNewPrivileges=yes\n", "NoNewPrivileges=no\n", 1))
	probes := make([]map[string]any, 0, len(in.Probes))
	for _, p := range in.Probes {
		probes = append(probes, map[string]any{"unit_name": "vsk-labs.service", "credential_name": p.CredentialName, "uid": p.UID, "gid": p.GID})
	}
	policy, _ := json.Marshal(map[string]any{"version": 1, "machine_id": machineID, "units": []string{"vsk-labs.service"}, "probes": probes})
	files[controllerArtifacts["native-policy"]] = append(policy, '\n')
	files[controllerArtifacts["sudoers"]] = []byte("# Generated by the native_credential_authority role; no arbitrary arguments.\nvsk-labs ALL=(root) NOPASSWD: /usr/local/bin/vsk-labs __native-credential-access-probe\nvsk-labs ALL=(root) NOPASSWD: /usr/local/bin/vsk-labs __native-credential-policy-check\n")
	files[controllerArtifacts["polkit"]] = []byte(controllerNativePolkit)
	return files, nil
}

const controllerNativePolkit = `// Generated by the native_credential_authority role; exact enrollment only.
const vskNativeUnits = ["vsk-labs.service"];
polkit.addRule(function(action, subject) {
    if (subject.user !== 'vsk-labs') return polkit.Result.NOT_HANDLED;
    if (action.id === 'io.systemd.credentials.encrypt') return polkit.Result.YES;
    if (action.id === 'io.systemd.credentials.decrypt') return polkit.Result.NO;
    if (action.id === 'org.freedesktop.systemd1.manage-unit-files' ||
        action.id === 'org.freedesktop.systemd1.reload-daemon') return polkit.Result.NO;
    if (action.id !== 'org.freedesktop.systemd1.manage-units') return polkit.Result.NOT_HANDLED;
    const unit = action.lookup('unit');
    if (action.lookup('verb') === 'restart' && vskNativeUnits.indexOf(unit) !== -1) return polkit.Result.YES;
    return polkit.Result.NO;
});
`
