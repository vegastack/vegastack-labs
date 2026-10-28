//go:build linux

package linuxrole

import (
	"bytes"
	"context"
	"os"
	"strconv"

	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/ingressconnector"
)

func VerifyControllerInstallResult(ctx context.Context, in ControllerInstallInput) (string, error) {
	foundation, e := verifyControllerFoundation(ctx, in)
	if e != nil {
		return "", e
	}
	if in.Stage == ControllerInstallStage {
		return foundation, nil
	}
	service, e := verifyControllerService(ctx, in)
	if e != nil {
		return "", e
	}
	if in.Stage == ControllerHandoffStage {
		return service, nil
	}
	connector, e := verifyControllerConnector(ctx, in)
	if e != nil {
		return "", e
	}
	return hostaction.Digest(map[string]string{"service": service, "connector": connector}), nil
}

// RunControllerInstall is the finite effect of an already claimed local plan.
// The executable's administrator entry obtains and validates that current claim
// before calling this function. No stage can create a human acknowledgement.
func RunControllerInstall(ctx context.Context, in ControllerInstallInput, version string) (changed bool, status string, resultDigest string, err error) {
	status = "failed"
	if os.Getuid() != 0 || os.Geteuid() != 0 || ValidateControllerInstallInput(in) != nil {
		return false, status, "", errNative
	}
	if err = VerifyControllerInstallPreconditions(ctx, in); err != nil {
		return false, status, "", err
	}
	switch in.Stage {
	case ControllerInstallStage:
		changed, err = InstallControllerFoundation(ctx, in, version)
	case ControllerHandoffStage:
		changed, err = installControllerService(ctx, in, version)
	case ControllerConnectorStage:
		var result ingressconnector.Result
		result, err = ingressconnector.NewNativeRuntime().Install(ctx, *in.Connector)
		changed = result.Changed
	default:
		return false, status, "", errNative
	}
	if err != nil {
		if changed {
			status = "partial"
		}
		return changed, status, "", err
	}
	resultDigest, err = VerifyControllerInstallResult(ctx, in)
	if err != nil {
		return changed, "partial", "", err
	}
	return changed, "installed-awaiting-native-verification", resultDigest, nil
}

func verifyControllerConnector(ctx context.Context, in ControllerInstallInput) (string, error) {
	if in.Connector == nil {
		return "", errInput
	}
	unit, e := ownedFile(ingressconnector.UnitPath, 0, 65536)
	if e != nil || !bytes.Equal(unit, ingressconnector.Unit(*in.Connector)) {
		return "", errNative
	}
	bin, e := ownedFile(ingressconnector.BinaryPath, 0, 128<<20)
	if e != nil || hostaction.BytesDigest(bin) != "sha256:"+ingressconnector.BinarySHA256 {
		return "", errNative
	}
	raw, e := roleCommand(ctx, "/usr/bin/systemctl", []string{"show", ingressconnector.UnitName, "--property=ActiveState,MainPID,FragmentPath,DropInPaths", "--no-pager"})
	if e != nil {
		return "", e
	}
	p := parseProperties(raw)
	pid, e := strconv.ParseInt(p["MainPID"], 10, 64)
	if e != nil || pid <= 1 || p["ActiveState"] != "active" || p["FragmentPath"] != ingressconnector.UnitPath || p["DropInPaths"] != "" {
		return "", errNative
	}
	return hostaction.Digest(map[string]any{"stage": "connector-running-awaiting-ingress-verification", "unit": hostaction.BytesDigest(unit), "binary": hostaction.BytesDigest(bin), "pid": pid, "input": hostaction.Digest(in)}), nil
}
