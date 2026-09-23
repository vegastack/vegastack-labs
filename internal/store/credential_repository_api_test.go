package store

import (
	"reflect"
	"testing"
)

// A future in-process caller must not regain a weaker credential transition
// path that skips the sealed lifecycle binding and consumer evidence.
func TestNoWeakerParallelTransitionAPIExists(t *testing.T) {
	typ := reflect.TypeOf(&CredentialRepository{})
	for _, name := range []string{"StageCredentialVersion", "AppendCredentialStatus"} {
		if _, ok := typ.MethodByName(name); ok {
			t.Fatalf("%s must not exist; the only append path is ApplyCredentialLifecycle", name)
		}
	}
}
