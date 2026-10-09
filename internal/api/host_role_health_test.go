package api

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/store"
	"testing"
)

type roleHealthAuthority struct {
	testAuthority
	epoch int64
}

func (a roleHealthAuthority) CurrentAuthority(context.Context) (store.AuthorityState, error) {
	return store.AuthorityState{InstanceID: "same-database-instance", RecoveryEpoch: a.epoch}, nil
}
func TestRoleHandoffHealthBindsDatabaseInstanceAndEpoch(t *testing.T) {
	app := &Application{config: Config{Authority: roleHealthAuthority{}}}
	got, err := app.Health(context.Background())
	if err != nil || got.InstanceID != "same-database-instance" || got.RecoveryEpoch != 0 {
		t.Fatal(got, err)
	}
	app.config.Authority = roleHealthAuthority{epoch: 1}
	if _, err = app.Health(context.Background()); err == nil {
		t.Fatal("changed recovery epoch paired with old health")
	}
}
