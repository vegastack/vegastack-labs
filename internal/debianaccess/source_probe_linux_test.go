//go:build linux

package debianaccess

import (
	"bytes"
	"testing"
)

func TestSourceRouteSnapshotExcludesOnlyTrafficCounters(t *testing.T) {
	before := []byte("Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\neth0 00000000 010200C0 0003 0 5 100 00000000 0 0 0\n")
	traffic := bytes.ReplaceAll(before, []byte("0003 0 5"), []byte("0003 2 99"))
	route := bytes.ReplaceAll(before, []byte("010200C0"), []byte("020200C0"))
	a, e := canonicalRouteTable(before, false)
	if e != nil {
		t.Fatal(e)
	}
	b, e := canonicalRouteTable(traffic, false)
	if e != nil || !bytes.Equal(a, b) {
		t.Fatal("traffic invalidated immutable routing")
	}
	c, e := canonicalRouteTable(route, false)
	if e != nil || bytes.Equal(a, c) {
		t.Fatal("route change not detected")
	}
	if _, e = canonicalRouteTable([]byte("header\nbroken\n"), false); e == nil {
		t.Fatal("malformed route accepted")
	}
}
