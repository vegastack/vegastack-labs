package server

import (
	"github.com/vegastack/vegastack-labs/internal/adapter/harbor"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostingplatform"
	"reflect"
	"testing"
)

func recoveryHostingFixture() (hostingConfiguration, []generated.HostingOwnedResource) {
	conf := hostingConfiguration{Harbor: &hostingHarbor{Resources: harbor.LifecycleRequest{
		Projects: []harbor.ProjectBinding{{Name: "project", KeepLast: 5}},
		Robots:   []harbor.RobotBinding{{Name: "robot$push", ReferenceID: "push-ref", Push: true}, {Name: "robot$pull", ReferenceID: "pull-ref"}},
	}}}
	owned := []generated.HostingOwnedResource{
		{Kind: "harbor-project", ExternalID: "2", ParentID: "project"},
		{Kind: "harbor-retention", ExternalID: "1", ParentID: "project"},
		{Kind: "harbor-robot", ExternalID: "7", ParentID: "push-ref"},
	}
	return conf, owned
}

func TestHostingRecoveryOwnershipMapsExactBindingsWithoutMutatingInputs(t *testing.T) {
	conf, owned := recoveryHostingFixture()
	originalHarbor := conf.Harbor
	originalOwned := append([]generated.HostingOwnedResource(nil), owned...)
	if e := applyHostingRecoveryOwnership(&conf, owned); e != nil {
		t.Fatal(e)
	}
	r := conf.Harbor.Resources
	if r.Projects[0].ID != 2 || r.Projects[0].RetentionID != 1 || r.Robots[0].ID != 7 || !r.Robots[0].ReconcileSecret || r.Robots[1].ID != 0 || r.Robots[1].ReconcileSecret {
		t.Fatal("incorrect recovery binding", r)
	}
	if originalHarbor.Resources.Projects[0].ID != 0 || originalHarbor.Resources.Projects[0].RetentionID != 0 || originalHarbor.Resources.Robots[0].ID != 0 || originalHarbor.Resources.Robots[0].ReconcileSecret || !reflect.DeepEqual(owned, originalOwned) {
		t.Fatal("recovery modified approved source inputs")
	}
}

func TestHostingRecoveryOwnershipRejectsUnrelatedOrAmbiguousBindings(t *testing.T) {
	cases := map[string]func(*hostingConfiguration, *[]generated.HostingOwnedResource){
		"unrelated-kind":          func(c *hostingConfiguration, r *[]generated.HostingOwnedResource) { (*r)[0].Kind = "coolify-project" },
		"unknown-parent":          func(c *hostingConfiguration, r *[]generated.HostingOwnedResource) { (*r)[0].ParentID = "other" },
		"unknown-robot-reference": func(c *hostingConfiguration, r *[]generated.HostingOwnedResource) { (*r)[2].ParentID = "other-ref" },
		"duplicate-binding":       func(c *hostingConfiguration, r *[]generated.HostingOwnedResource) { *r = append(*r, (*r)[0]) },
		"duplicate-robot-id": func(c *hostingConfiguration, r *[]generated.HostingOwnedResource) {
			*r = append(*r, generated.HostingOwnedResource{Kind: "harbor-robot", ExternalID: "7", ParentID: "pull-ref"})
		},
		"noncanonical-id": func(c *hostingConfiguration, r *[]generated.HostingOwnedResource) { (*r)[0].ExternalID = "02" },
		"zero-id":         func(c *hostingConfiguration, r *[]generated.HostingOwnedResource) { (*r)[0].ExternalID = "0" },
		"negative-id":     func(c *hostingConfiguration, r *[]generated.HostingOwnedResource) { (*r)[0].ExternalID = "-1" },
		"configured-project-mismatch": func(c *hostingConfiguration, r *[]generated.HostingOwnedResource) {
			c.Harbor.Resources.Projects[0].ID = 3
		},
		"configured-retention-mismatch": func(c *hostingConfiguration, r *[]generated.HostingOwnedResource) {
			c.Harbor.Resources.Projects[0].RetentionID = 3
		},
		"configured-robot-mismatch": func(c *hostingConfiguration, r *[]generated.HostingOwnedResource) {
			c.Harbor.Resources.Robots[0].ID = 8
		},
		"retention-without-project": func(c *hostingConfiguration, r *[]generated.HostingOwnedResource) { *r = (*r)[1:] },
		"duplicate-configured-project": func(c *hostingConfiguration, r *[]generated.HostingOwnedResource) {
			c.Harbor.Resources.Projects = append(c.Harbor.Resources.Projects, c.Harbor.Resources.Projects[0])
		},
		"duplicate-configured-robot-reference": func(c *hostingConfiguration, r *[]generated.HostingOwnedResource) {
			c.Harbor.Resources.Robots[1].ReferenceID = "push-ref"
		},
		"coolify-mixed": func(c *hostingConfiguration, r *[]generated.HostingOwnedResource) { c.Coolify = &hostingCoolify{} },
		"platform-mixed": func(c *hostingConfiguration, r *[]generated.HostingOwnedResource) {
			c.Platform = &hostingplatform.Input{}
		},
		"no-resources": func(c *hostingConfiguration, r *[]generated.HostingOwnedResource) { *r = nil },
	}
	for name, modify := range cases {
		t.Run(name, func(t *testing.T) {
			conf, owned := recoveryHostingFixture()
			modify(&conf, &owned)
			original := conf.Harbor
			if e := applyHostingRecoveryOwnership(&conf, owned); e == nil {
				t.Fatal("accepted invalid recovery binding")
			}
			if conf.Harbor != original {
				t.Fatal("failed recovery changed protected configuration")
			}
		})
	}
}
