package backup

import (
	"strings"
	"testing"
)

func TestParseObjectPathAcceptsValidReticObjects(t *testing.T) {
	name := strings.Repeat("a", 64)
	cases := map[string]struct {
		path     string
		objType  string
		retained bool
		isLock   bool
		isConfig bool
	}{
		"config":    {"/repo-a/config", "config", true, false, true},
		"data":      {"/repo-a/data/" + name, "data", true, false, false},
		"index":     {"/repo-a/index/" + name, "index", true, false, false},
		"keys":      {"/repo-a/keys/" + name, "keys", true, false, false},
		"snapshots": {"/repo-a/snapshots/" + name, "snapshots", true, false, false},
		"locks":     {"/repo-a/locks/" + name, "locks", false, true, false},
	}
	for label, fixture := range cases {
		t.Run(label, func(t *testing.T) {
			got, ok := parseObjectPath(fixture.path, "repo-a")
			if !ok || got.objectType != fixture.objType || got.retained != fixture.retained || got.isLock != fixture.isLock || got.isConfig != fixture.isConfig {
				t.Fatalf("parse %q = %#v ok=%v", fixture.path, got, ok)
			}
		})
	}
}

func TestParseObjectPathRejectsUnsafePaths(t *testing.T) {
	name := strings.Repeat("a", 64)
	for label, path := range map[string]string{
		"traversal type":    "/repo-a/../config",
		"traversal name":    "/repo-a/data/..",
		"wrong repository":  "/repo-b/data/" + name,
		"unknown type":      "/repo-a/blobs/" + name,
		"config with name":  "/repo-a/config/" + name,
		"data without name": "/repo-a/data",
		"short name":        "/repo-a/data/abcd",
		"uppercase name":    "/repo-a/data/" + strings.Repeat("A", 64),
		"non-hex name":      "/repo-a/data/" + strings.Repeat("g", 64),
		"nested name":       "/repo-a/data/" + name + "/extra",
		"empty":             "",
		"backslash segment": "/repo-a/data/" + name[:63] + "\\",
		"nul in name":       "/repo-a/data/" + name[:63] + "\x00",
		"absolute-only":     "/repo-a",
	} {
		t.Run(label, func(t *testing.T) {
			if _, ok := parseObjectPath(path, "repo-a"); ok {
				t.Fatalf("parse accepted unsafe path %q", path)
			}
		})
	}
}

func TestRetainedObjectTypesAreImmutableSet(t *testing.T) {
	for _, retained := range []string{"config", "keys", "data", "index", "snapshots"} {
		if _, ok := retainedObjectTypes[retained]; !ok {
			t.Fatalf("%s is not in the retained (immutable) set", retained)
		}
	}
	if _, ok := retainedObjectTypes["locks"]; ok {
		t.Fatal("locks must be mutable, not retained")
	}
}
