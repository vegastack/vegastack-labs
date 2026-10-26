package contractgen

import (
	"bytes"
	"regexp"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/metadata"
)

func TestNetworkStatusBrowserMethodsRemainDistinct(t *testing.T) {
	endpoints, err := browserReadEndpoints(metadata.Current())
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	renderFiniteReadClient(&output, endpoints)
	source := output.String()
	for _, method := range []string{"getNetworkMesh", "getNetworkIngress", "listPeople", "getPlan", "getGate"} {
		if strings.Count(source, "  readonly "+method+":") != 1 || strings.Count(source, "    async "+method+"(") != 1 {
			t.Errorf("expected one interface declaration and implementation for %s", method)
		}
	}
	if strings.Contains(source, "readonly getNetwork:") || strings.Contains(source, "async getNetwork(") {
		t.Fatal("network status routes retained the ambiguous shared method")
	}
	seen := make(map[string]bool)
	for _, match := range regexp.MustCompile(`(?m)^  readonly ([A-Za-z0-9_]+):`).FindAllStringSubmatch(source, -1) {
		if seen[match[1]] {
			t.Errorf("duplicate generated read-client method %s", match[1])
		}
		seen[match[1]] = true
	}
}
