//go:build linux

package nativecredential

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/godbus/dbus/v5"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
)

var errAppliedUnit = errors.New("native credential applied unit unavailable")

type CredentialSource struct{ ID, AbsolutePath string }

type AppliedUnitSnapshot struct {
	UnitName, MachineID, BootID, InvocationID, ActiveState string
	MainPID                                                uint32
	ExecMainStartMonotonicUSec                             uint64
	User, Group                                            string
	NeedDaemonReload                                       bool
	EncryptedSources                                       []CredentialSource
}

type AppliedUnitReader interface {
	ObserveAppliedUnit(context.Context, string) (AppliedUnitSnapshot, error)
}

type SystemdUnitReader struct{}

func (SystemdUnitReader) ObserveAppliedUnit(ctx context.Context, unit string) (AppliedUnitSnapshot, error) {
	return ObserveAppliedUnit(ctx, unit)
}

// ObserveAppliedUnit reads the manager's applied properties, including drop-ins,
// rather than parsing unit files or human-oriented systemctl output.
func ObserveAppliedUnit(ctx context.Context, unit string) (AppliedUnitSnapshot, error) {
	if ctx == nil || ctx.Err() != nil || !unitNamePattern.MatchString(unit) || strings.Contains(unit, "..") || strings.Contains(unit, "@.service") {
		return AppliedUnitSnapshot{}, errAppliedUnit
	}
	conn, err := dbus.SystemBusPrivate()
	if err != nil {
		return AppliedUnitSnapshot{}, errAppliedUnit
	}
	defer conn.Close()
	if conn.Auth(nil) != nil || conn.Hello() != nil {
		return AppliedUnitSnapshot{}, errAppliedUnit
	}
	manager := conn.Object("org.freedesktop.systemd1", "/org/freedesktop/systemd1")
	var path dbus.ObjectPath
	if manager.CallWithContext(ctx, "org.freedesktop.systemd1.Manager.GetUnit", 0, unit).Store(&path) != nil || !path.IsValid() {
		return AppliedUnitSnapshot{}, errAppliedUnit
	}
	object := conn.Object("org.freedesktop.systemd1", path)
	var unitProps, serviceProps map[string]dbus.Variant
	if object.CallWithContext(ctx, "org.freedesktop.DBus.Properties.GetAll", 0, "org.freedesktop.systemd1.Unit").Store(&unitProps) != nil ||
		object.CallWithContext(ctx, "org.freedesktop.DBus.Properties.GetAll", 0, "org.freedesktop.systemd1.Service").Store(&serviceProps) != nil {
		return AppliedUnitSnapshot{}, errAppliedUnit
	}
	snapshot, err := decodeAppliedUnit(unit, unitProps, serviceProps)
	if err != nil {
		return AppliedUnitSnapshot{}, err
	}
	machine, err := os.ReadFile("/etc/machine-id")
	if err != nil || !machineIDPattern.MatchString(strings.TrimSpace(string(machine))) {
		return AppliedUnitSnapshot{}, errAppliedUnit
	}
	boot, err := currentBootID()
	if err != nil {
		return AppliedUnitSnapshot{}, errAppliedUnit
	}
	snapshot.MachineID, snapshot.BootID = strings.TrimSpace(string(machine)), boot
	return snapshot, nil
}

func decodeAppliedUnit(unit string, unitProps, serviceProps map[string]dbus.Variant) (AppliedUnitSnapshot, error) {
	get := func(values map[string]dbus.Variant, key string) any { return values[key].Value() }
	id, okID := get(unitProps, "Id").(string)
	load, okLoad := get(unitProps, "LoadState").(string)
	active, okActive := get(unitProps, "ActiveState").(string)
	reload, okReload := get(unitProps, "NeedDaemonReload").(bool)
	invocation, okInvocation := get(unitProps, "InvocationID").([]byte)
	pid, okPID := get(serviceProps, "MainPID").(uint32)
	started, okStarted := get(serviceProps, "ExecMainStartTimestampMonotonic").(uint64)
	user, okUser := get(serviceProps, "User").(string)
	group, okGroup := get(serviceProps, "Group").(string)
	rawSources, okSources := get(serviceProps, "LoadCredentialEncrypted").([][]interface{})
	if !okID || !okLoad || !okActive || !okReload || !okInvocation || !okPID || !okStarted || !okUser || !okGroup || !okSources ||
		id != unit || load != "loaded" || reload || len(invocation) != 16 ||
		len(rawSources) == 0 || len(rawSources) > 64 {
		return AppliedUnitSnapshot{}, errAppliedUnit
	}
	sources := make([]CredentialSource, 0, len(rawSources))
	seen := make(map[string]bool, len(rawSources))
	for _, pair := range rawSources {
		if len(pair) != 2 {
			return AppliedUnitSnapshot{}, errAppliedUnit
		}
		name, okName := pair[0].(string)
		path, okPath := pair[1].(string)
		if !okName || !okPath || !credentialNamePattern.MatchString(name) || seen[name] || !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return AppliedUnitSnapshot{}, errAppliedUnit
		}
		seen[name] = true
		sources = append(sources, CredentialSource{ID: name, AbsolutePath: path})
	}
	return AppliedUnitSnapshot{UnitName: unit, InvocationID: hex.EncodeToString(invocation), ActiveState: active,
		MainPID: pid, ExecMainStartMonotonicUSec: started, User: user, Group: group, NeedDaemonReload: reload, EncryptedSources: sources}, nil
}

func validateAppliedSource(snapshot AppliedUnitSnapshot, binding credentialref.LifecycleBinding, reader credentialref.NativeConsumerBinding, expectedPath string) error {
	if snapshot.UnitName != reader.UnitName || snapshot.ActiveState != "active" || snapshot.NeedDaemonReload ||
		reader.LoadedName == "" || reader.LoadedName != credentialref.LoadedNameForVersion(binding.NativeArtifactConsumerID, binding.ReferenceID, binding.MaterialVersion) ||
		!filepath.IsAbs(expectedPath) || filepath.Clean(expectedPath) != expectedPath || len(snapshot.EncryptedSources) != 1 {
		return errAppliedUnit
	}
	source := snapshot.EncryptedSources[0]
	if source.ID != reader.LoadedName || source.AbsolutePath != expectedPath {
		return errAppliedUnit
	}
	return nil
}
