package server

import (
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
)

func TestIngressControllerPilotIsDerivedOnlyFromConsistentPinnedProfile(t *testing.T) {
	setup := &generated.ControllerSetupPilotPolicy{AdministratorPrincipalID: "omkar-mohanta"}
	bootstrap := func(owner, device string) *generated.IngressBootstrapPolicy {
		return &generated.IngressBootstrapPolicy{Change: generated.IngressChange{OwnerID: owner, DeviceID: device}}
	}
	readPilot := func(owner, device string) *generated.IngressControllerReadPilot {
		return &generated.IngressControllerReadPilot{Change: generated.IngressChange{OwnerID: owner, DeviceID: device}}
	}
	for _, test := range []struct {
		name    string
		profile serverconfig.Profile
		want    string // "owner/device", or "" for no exception
	}{
		{"limited setup plus bootstrap pins", serverconfig.Profile{ControllerSetupPilot: setup, IngressBootstrap: bootstrap("omkar-mohanta", "controller-pilot")}, "omkar-mohanta/controller-pilot"},
		{"read pilot alone with limited setup", serverconfig.Profile{ControllerSetupPilot: setup, IngressControllerReadPilot: readPilot("omkar-mohanta", "controller-pilot")}, "omkar-mohanta/controller-pilot"},
		{"bootstrap and read pilot agree", serverconfig.Profile{ControllerSetupPilot: setup, IngressBootstrap: bootstrap("omkar-mohanta", "controller-pilot"), IngressControllerReadPilot: readPilot("omkar-mohanta", "controller-pilot")}, "omkar-mohanta/controller-pilot"},
		{"no limited controller setup selected", serverconfig.Profile{IngressBootstrap: bootstrap("omkar-mohanta", "controller-pilot")}, ""},
		{"no ingress pin at all", serverconfig.Profile{ControllerSetupPilot: setup}, ""},
		{"owner is not the pinned setup administrator", serverconfig.Profile{ControllerSetupPilot: setup, IngressBootstrap: bootstrap("someone-else", "controller-pilot")}, ""},
		{"bootstrap and read pilot disagree on the device", serverconfig.Profile{ControllerSetupPilot: setup, IngressBootstrap: bootstrap("omkar-mohanta", "controller-pilot"), IngressControllerReadPilot: readPilot("omkar-mohanta", "other-device")}, ""},
		{"bootstrap and read pilot disagree on the owner", serverconfig.Profile{ControllerSetupPilot: setup, IngressBootstrap: bootstrap("omkar-mohanta", "controller-pilot"), IngressControllerReadPilot: readPilot("someone-else", "controller-pilot")}, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := ""
			if p := ingressControllerPilot(test.profile); p != nil {
				got = p.PrincipalID + "/" + p.DeviceID
			}
			if got != test.want {
				t.Fatalf("pilot %q want %q", got, test.want)
			}
		})
	}
}
