//go:build linux

package nativecredential

import (
	"testing"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
)

func TestLifecycleLoadedNameMatchesNativeResolver(t *testing.T) {
	for _, test := range [][3]string{
		{"consumer-a", "reference-a", "version-a"},
		{"consumer-b", "reference-b", "version-b"},
		{"invalid space", "reference-a", "version-a"},
	} {
		if got, want := credentialref.LoadedNameForVersion(test[0], test[1], test[2]), LoadedNameForVersion(test[0], test[1], test[2]); got != want {
			t.Fatalf("loaded credential name differs for %q: lifecycle=%q resolver=%q", test, got, want)
		}
	}
}
