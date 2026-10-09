package hostaction

import "testing"

func TestProductionDispatcherDoesNotExposeFixture(t *testing.T) {
	for _, id := range []string{"test.write-file", "shell", "ansible.shell", "../bin/sh", ""} {
		if _, ok := ProductionDispatcher().Lookup(id, "1.0.0"); ok {
			t.Fatalf("production exposed %q", id)
		}
	}
}
