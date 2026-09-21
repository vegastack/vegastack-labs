//go:build linux

package nativecredential

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAccessProbeIdentity(t *testing.T) {
	request := AccessProbeRequest{UID: 1002, GID: 1003, UnitName: "example.service", CredentialName: "credential-a", MainPID: 1234, ProcessStartTicks: 100, BootID: "fixture-boot"}
	if _, err := ProbeReader(context.Background(), request); err == nil {
		t.Fatal("unqualified process accepted")
	}
	request.UID = 0
	if _, err := ProbeReader(context.Background(), request); err == nil {
		t.Fatal("root probe accepted")
	}
}

func TestAccessProbeValidation(t *testing.T) {
	base := AccessProbeRequest{UID: 1002, GID: 1003, UnitName: "example.service", CredentialName: "credential-a", MainPID: 1234, ProcessStartTicks: 100, BootID: "a0b1c2d3-e4f5-6789-abcd-0123456789ab"}
	cases := []struct {
		name   string
		change func(*AccessProbeRequest)
	}{
		{"root-gid", func(r *AccessProbeRequest) { r.GID = 0 }},
		{"wildcard-unit", func(r *AccessProbeRequest) { r.UnitName = "*.service" }},
		{"path-unit", func(r *AccessProbeRequest) { r.UnitName = "../evil.service" }},
		{"template-unit", func(r *AccessProbeRequest) { r.UnitName = "app@.service" }},
		{"path-credential", func(r *AccessProbeRequest) { r.CredentialName = "../secret" }},
		{"zero-pid", func(r *AccessProbeRequest) { r.MainPID = 0 }},
		{"zero-start", func(r *AccessProbeRequest) { r.ProcessStartTicks = 0 }},
		{"invalid-boot", func(r *AccessProbeRequest) { r.BootID = "bad" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := base
			tc.change(&r)
			if err := r.Validate(); err == nil {
				t.Fatal("invalid request accepted")
			}
		})
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}
}

func TestProbeChildInputBound(t *testing.T) {
	input := strings.NewReader(strings.Repeat("x", 4097))
	if _, err := decodeAccessProbeRequest(input); err == nil {
		t.Fatal("oversized request accepted")
	}
}

func TestProbePolicyExactEnrollment(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned policy fixture requires root")
	}
	path := filepath.Join(t.TempDir(), "policy.json")
	machine := `"machine_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",`
	probe := `"probes":[{"unit_name":"alpha.service","credential_name":"credential-a","uid":1001,"gid":1001}]`
	for _, tc := range []struct {
		name, body string
		good       bool
	}{
		{"valid", `{"version":1,` + machine + `"units":["alpha.service","beta.service"],` + probe + `}`, true},
		{"wildcard", `{"version":1,` + machine + `"units":["*.service"],` + probe + `}`, false},
		{"duplicate", `{"version":1,` + machine + `"units":["alpha.service","alpha.service"],` + probe + `}`, false},
		{"unsorted", `{"version":1,` + machine + `"units":["beta.service","alpha.service"],` + probe + `}`, false},
		{"unknown-field", `{"version":1,` + machine + `"units":["alpha.service"],` + probe + `,"allow_all":true}`, false},
		{"empty", `{"version":1,` + machine + `"units":[],` + probe + `}`, false},
		{"root-reader", `{"version":1,` + machine + `"units":["alpha.service"],"probes":[{"unit_name":"alpha.service","credential_name":"credential-a","uid":0,"gid":1001}]}`, false},
		{"wrong-unit", `{"version":1,` + machine + `"units":["beta.service"],` + probe + `}`, false},
		{"duplicate-probe", `{"version":1,` + machine + `"units":["alpha.service"],"probes":[{"unit_name":"alpha.service","credential_name":"credential-a","uid":1001,"gid":1001},{"unit_name":"alpha.service","credential_name":"credential-a","uid":1001,"gid":1001}]}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := parseProbePolicy([]byte(tc.body))
			if (err == nil) != tc.good {
				t.Fatalf("policy acceptance mismatch: %v", err)
			}
		})
	}
	if trustedParentDirectories(path) {
		valid := `{"version":1,"machine_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","units":["alpha.service"],"probes":[{"unit_name":"alpha.service","credential_name":"credential-a","uid":1001,"gid":1001}]}`
		if err := os.WriteFile(path, []byte(valid), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readProbePolicy(path); err != nil {
			t.Fatalf("trusted root-owned policy rejected: %v", err)
		}
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := readProbePolicy(path); err == nil {
		t.Fatal("policy in mutable parent accepted")
	}
}

func TestExactUnitCgroupMembership(t *testing.T) {
	if !cgroupContainsExactUnit("0::/system.slice/alpha.service\n", "alpha.service") {
		t.Fatal("exact unit missed")
	}
	for _, value := range []string{"0::/system.slice/alpha.service-extra\n", "0::/system.slice/alpha.service.scope\n", "0::/system.slice/beta.service\n"} {
		if cgroupContainsExactUnit(value, "alpha.service") {
			t.Fatal("different unit accepted")
		}
	}
}

func TestProbeRejectsSymlinkAndReturnsOnlyMetadata(t *testing.T) {
	root:=t.TempDir()
	unitDir:=filepath.Join(root,"alpha.service")
	if err:=os.Mkdir(unitDir,0o700);err!=nil { t.Fatal(err) }
	if err:=os.WriteFile(filepath.Join(unitDir,"credential-a"),[]byte("synthetic-fixture"),0o600);err!=nil { t.Fatal(err) }
	if err:=os.Symlink("credential-a",filepath.Join(unitDir,"credential-link"));err!=nil { t.Fatal(err) }
	opened:=probeCredentialFileAt(root,"alpha.service","credential-a")
	if opened.Status!=AccessProbeOpened || opened.Inode==0 || opened.Mode==0 { t.Fatalf("fixture open metadata missing: %+v",opened) }
	if got:=probeCredentialFileAt(root,"alpha.service","credential-link");got.Status!=AccessProbeUnknown { t.Fatalf("symlink accepted: %+v",got) }
}
