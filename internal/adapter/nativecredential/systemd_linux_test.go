//go:build linux

package nativecredential

import (
	"context"
	"testing"

	"github.com/godbus/dbus/v5"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
)

func TestAppliedEncryptedSource(t *testing.T) {
	binding := credentialref.LifecycleBinding{
		ReferenceID: "reference-a", MaterialVersion: "version-a", NativeArtifactConsumerID: "consumer-a",
		CiphertextFingerprint: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	reader := credentialref.NativeConsumerBinding{UnitName: "consumer.service", LoadedName: credentialref.LoadedNameForVersion("consumer-a", "reference-a", "version-a")}
	source := "/sealed/" + reader.LoadedName
	snapshot := AppliedUnitSnapshot{UnitName: reader.UnitName, ActiveState: "active", EncryptedSources: []CredentialSource{{ID: reader.LoadedName, AbsolutePath: source}}}
	if err := validateAppliedSource(snapshot, binding, reader, source); err != nil {
		t.Fatalf("exact source rejected: %v", err)
	}
	for name, change := range map[string]func(*AppliedUnitSnapshot){
		"wrong-name":       func(s *AppliedUnitSnapshot) { s.EncryptedSources[0].ID = "credential-other" },
		"substituted-path": func(s *AppliedUnitSnapshot) { s.EncryptedSources[0].AbsolutePath = "../../sealed" },
		"extra-source":     func(s *AppliedUnitSnapshot) { s.EncryptedSources = append(s.EncryptedSources, s.EncryptedSources[0]) },
		"pending-reload":   func(s *AppliedUnitSnapshot) { s.NeedDaemonReload = true },
	} {
		t.Run(name, func(t *testing.T) {
			changed := snapshot
			changed.EncryptedSources = append([]CredentialSource(nil), snapshot.EncryptedSources...)
			change(&changed)
			if err := validateAppliedSource(changed, binding, reader, source); err == nil {
				t.Fatal("changed applied credential source accepted")
			}
		})
	}
	if _, err := ObserveAppliedUnit(context.Background(), "../other.service"); err == nil {
		t.Fatal("invalid unit accepted")
	}
}

func TestTypedAppliedUnitProperties(t *testing.T) {
	unit := "consumer.service"
	unitProperties := map[string]dbus.Variant{
		"Id": dbus.MakeVariant(unit), "LoadState": dbus.MakeVariant("loaded"), "ActiveState": dbus.MakeVariant("active"),
		"NeedDaemonReload": dbus.MakeVariant(false), "InvocationID": dbus.MakeVariant([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}),
	}
	serviceProperties := map[string]dbus.Variant{
		"MainPID": dbus.MakeVariant(uint32(42)), "ExecMainStartTimestampMonotonic": dbus.MakeVariant(uint64(123)),
		"User": dbus.MakeVariant("vsk-test"), "Group": dbus.MakeVariant("vsk-test"),
		"LoadCredentialEncrypted": dbus.MakeVariant([][]interface{}{{"credential-a", "/sealed/credential-a"}}),
	}
	if _, err := decodeAppliedUnit(unit, unitProperties, serviceProperties); err != nil {
		t.Fatalf("typed properties rejected: %v", err)
	}
	delete(serviceProperties, "ExecMainStartTimestampMonotonic")
	if _, err := decodeAppliedUnit(unit, unitProperties, serviceProperties); err == nil {
		t.Fatal("missing process start accepted")
	}
}

func TestAppliedMultipleEncryptedSources(t *testing.T) {
	b := credentialref.LifecycleBinding{ReferenceID: "reference-a", MaterialVersion: "version-a", NativeArtifactConsumerID: "consumer-a"}
	name := credentialref.LoadedNameForVersion("consumer-a", "reference-a", "version-a")
	other := credentialref.LoadedNameForVersion("consumer-a", "reference-b", "version-a")
	r := credentialref.NativeConsumerBinding{UnitName: "control.service", LoadedName: name}
	x := AppliedUnitSnapshot{UnitName: r.UnitName, ActiveState: "active", EncryptedSources: []CredentialSource{{ID: other, AbsolutePath: "/sealed/" + other}, {ID: name, AbsolutePath: "/sealed/" + name}}}
	if err := validateAppliedSource(x, b, r, "/sealed/"+name); err != nil {
		t.Fatalf("independently named target sources rejected: %v", err)
	}
	for kind, change := range map[string]func(*AppliedUnitSnapshot){
		"duplicate":        func(s *AppliedUnitSnapshot) { s.EncryptedSources = append(s.EncryptedSources, s.EncryptedSources[0]) },
		"foreign-root":     func(s *AppliedUnitSnapshot) { s.EncryptedSources[0].AbsolutePath = "/foreign/" + other },
		"swapped-name":     func(s *AppliedUnitSnapshot) { s.EncryptedSources[0].ID = name },
		"missing-selected": func(s *AppliedUnitSnapshot) { s.EncryptedSources = s.EncryptedSources[:1] },
	} {
		t.Run(kind, func(t *testing.T) {
			changed := x
			changed.EncryptedSources = append([]CredentialSource(nil), x.EncryptedSources...)
			change(&changed)
			if validateAppliedSource(changed, b, r, "/sealed/"+name) == nil {
				t.Fatal("invalid source set accepted")
			}
		})
	}
}
