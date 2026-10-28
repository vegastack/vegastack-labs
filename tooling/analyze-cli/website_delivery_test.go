package main

import (
	"slices"
	"strings"
	"testing"
)

func TestConnectorPrivateMainEdgeRequiresBothExactClosures(t *testing.T) {
	var main, runtime listedPackage
	for key, seal := range websiteDeliverySourceSeals {
		if strings.HasPrefix(key, "cmd/vsk-labs|") && strings.Contains(key, "host_action_linux.go") {
			main = controllerSealFixture(t, key, seal)
		}
		if strings.HasPrefix(key, "internal/ingressconnector|") && strings.Contains(key, "native_linux.go") {
			runtime = controllerSealFixture(t, key, seal)
		}
	}
	if main.ImportPath == "" || runtime.ImportPath == "" {
		t.Fatal("missing Linux source pair")
	}
	if !websiteDeliveryPrivateMainEdge([]listedPackage{main, runtime}, controllerTestModule) {
		t.Fatal("exact private action pair denied")
	}
	for _, index := range []int{0, 1} {
		for _, variant := range []string{"missing", "import", "source", "cgo"} {
			t.Run(string(rune('0'+index))+"/"+variant, func(t *testing.T) {
				pair := []listedPackage{main, runtime}
				switch variant {
				case "missing":
					pair = slices.Delete(pair, index, index+1)
				case "import":
					pair[index].Imports = append(slices.Clone(pair[index].Imports), "net/rpc")
				case "source":
					pair[index].GoFiles = append(slices.Clone(pair[index].GoFiles), "unreviewed.go")
				case "cgo":
					pair[index].CgoFiles = []string{"unreviewed.go"}
				}
				if websiteDeliveryPrivateMainEdge(pair, controllerTestModule) {
					t.Fatal("unsealed pair inherited private action edge")
				}
			})
		}
	}
	// A direct portable-client dependency remains visible to its ordinary guards.
	cli := controllerTestModule + "/internal/cli"
	packages := []listedPackage{main, runtime, {ImportPath: cli, Imports: []string{runtime.ImportPath}}}
	if !moduleDependencyClosure(packages, cli)[runtime.ImportPath] {
		t.Fatal("direct CLI edge was hidden")
	}
}

func TestConnectorPruningRemovesOnlyExactLinuxRoleEdge(t *testing.T) {
	var role, connector listedPackage
	for key, seal := range websiteDeliverySourceSeals {
		if strings.HasPrefix(key, "internal/linuxrole|") && strings.Contains(key, "runtime_linux.go") {
			role = controllerSealFixture(t, key, seal)
		}
		if strings.HasPrefix(key, "internal/ingressconnector|") && strings.Contains(key, "native_linux.go") {
			connector = controllerSealFixture(t, key, seal)
		}
	}
	if role.ImportPath == "" || connector.ImportPath == "" {
		t.Fatal("missing role/connector source pair")
	}
	cli := listedPackage{ImportPath: controllerTestModule + "/internal/cli", Imports: []string{role.ImportPath}}
	sibling := listedPackage{ImportPath: controllerTestModule + "/internal/hostaction"}
	packages := []listedPackage{cli, role, connector, sibling}
	pruning := websiteDeliveryDependencyPruning(packages, controllerTestModule)
	closure := moduleDependencyClosurePruned(packages, cli.ImportPath, pruning)
	if closure[connector.ImportPath] || !closure[role.ImportPath] || !closure[sibling.ImportPath] {
		t.Fatal("pruning did not preserve other role edges")
	}
	packages[0].Imports = append(slices.Clone(cli.Imports), connector.ImportPath)
	if !moduleDependencyClosurePruned(packages, cli.ImportPath, pruning)[connector.ImportPath] {
		t.Fatal("direct CLI connector edge inherited native pruning")
	}
	packages[0] = cli
	for _, index := range []int{1, 2} {
		saved := packages[index]
		packages[index].GoFiles = append(slices.Clone(saved.GoFiles), "unreviewed.go")
		if len(websiteDeliveryDependencyPruning(packages, controllerTestModule)) != 0 {
			t.Fatal("changed role/connector pair inherited pruning")
		}
		packages[index] = saved
	}
}
