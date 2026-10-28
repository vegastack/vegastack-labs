package serverconfig

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
	"testing"
)

func TestOperationsProtectedScopeFreezesAndRejectsAmbiguity(t *testing.T) {
	b := []generated.OperationsBeszelBinding{{Schema: generated.SchemaIDOperationsBeszelBinding, SchemaVersion: "1.0.0", Endpoint: "https://monitor.example", RecordID: "abcdefghijklmno", TargetID: "synthetic-host", ReferenceID: "beszel-read", MaterialVersion: "v1", StaleAfterSeconds: 60}}
	out, _, e := FreezeOperations(b, nil)
	if e != nil {
		t.Fatal(e)
	}
	b[0].TargetID = "changed"
	if out[0].TargetID != "synthetic-host" {
		t.Fatal("profile aliases mutable input")
	}
	for _, target := range []string{"vsk-node-04", "vsk-node-05"} {
		bad := append([]generated.OperationsBeszelBinding(nil), out...)
		bad[0].TargetID = target
		if _, _, e = FreezeOperations(bad, nil); e == nil {
			t.Fatal("excluded target accepted")
		}
	}
	for _, endpoint := range []string{"http://monitor.example", "https://user:secret@monitor.example", "https://monitor.example/path", "https://monitor.example?token=seed"} {
		bad := append([]generated.OperationsBeszelBinding(nil), out...)
		bad[0].Endpoint = endpoint
		if _, _, e = FreezeOperations(bad, nil); e == nil {
			t.Fatal("unsafe endpoint accepted", endpoint)
		}
	}
	if _, _, e = FreezeOperations(append(out, out...), nil); e == nil {
		t.Fatal("duplicate target accepted")
	}
}
