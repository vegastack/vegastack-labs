package metadata

import (
	"strings"
	"testing"
)

func TestMinimalNodeCommandsAreUniqueAndAvailable(t *testing.T) {
	r := Current()
	for _, name := range []string{"node discover", "node add", "node inspect"} {
		count := 0
		for _, c := range r.Commands {
			if strings.Join(c.Path, " ") == name {
				count++
				if c.Availability == AvailabilityPlanned {
					t.Fatalf("%s remains planned", name)
				}
			}
		}
		if count != 1 {
			t.Fatalf("%s definitions: %d", name, count)
		}
	}
}
