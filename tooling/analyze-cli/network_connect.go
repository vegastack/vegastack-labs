package main

import (
	"slices"
	"strings"
)

// #277 operator-approved exact client/profile source variants. Historical seals remain unchanged.
var networkConnectSourceSeals = map[string]hostActionSourceSeal{
	"internal/localapi|apply_bound.go,approval_client.go,audit_client.go,authorization_grants.go,backup_client.go,client.go,credential_client.go,credential_lifecycle_client.go,database_client.go,gates_client.go,hosts_client.go,listener.go,listener_linux.go,network_endpoints.go,qualification_client.go,qualification_producer.go,restore_client.go,schedule_client.go": {imports: []string{"bytes", "context", "crypto/sha256", "encoding/hex", "encoding/json", "errors", "github.com/vegastack/vegastack-labs/internal/credentialref", "github.com/vegastack/vegastack-labs/internal/failure", "github.com/vegastack/vegastack-labs/internal/generated", "github.com/vegastack/vegastack-labs/internal/hostaction", "github.com/vegastack/vegastack-labs/internal/localtransport", "github.com/vegastack/vegastack-labs/internal/networkconnect", "github.com/vegastack/vegastack-labs/internal/principal", "github.com/vegastack/vegastack-labs/internal/result", "github.com/vegastack/vegastack-labs/internal/runprotocol", "github.com/vegastack/vegastack-labs/internal/serverconfig", "github.com/vegastack/vegastack-labs/internal/sshtransport", "golang.org/x/sys/unix", "io", "mime", "net", "os", "path/filepath", "runtime", "strconv", "strings", "sync", "time"}, digest: "f9cbc7f5bb00ca5ffe8b41d738aa6cc5ae19a497688424f57c2e73ef66f5c169"},
	"internal/networkconnect|client.go,endpoint.go,private_key_unix.go": {imports: []string{"context", "crypto/sha256", "crypto/tls", "encoding/hex", "encoding/json", "github.com/vegastack/vegastack-labs/internal/failure", "github.com/vegastack/vegastack-labs/internal/generated", "golang.org/x/crypto/ssh", "golang.org/x/sys/unix", "io", "net", "net/http", "net/netip", "net/url", "os", "path/filepath", "regexp", "strconv", "strings", "time"}, digest: "e49ac1e59c6df7ee20b5870ec47efde514530a0b75698a987ffc86dce20bbcef"},
	"internal/serverconfig|profile.go,profile_linux.go,restic.go":       {imports: []string{"bytes", "context", "crypto/sha256", "encoding/hex", "encoding/json", "github.com/vegastack/vegastack-labs/internal/backupidentity", "github.com/vegastack/vegastack-labs/internal/failure", "github.com/vegastack/vegastack-labs/internal/generated", "github.com/vegastack/vegastack-labs/internal/principal", "golang.org/x/sys/unix", "io", "io/fs", "net/netip", "net/url", "os", "path/filepath", "regexp", "runtime", "strings", "time"}, digest: "ee6effa9daa424f89d078a6b245558aa203fae48cac581d728efb1fcca5aecae"},
	"internal/localapi|apply_bound.go,approval_client.go,audit_client.go,authorization_grants.go,backup_client.go,client.go,credential_client.go,credential_lifecycle_client.go,database_client.go,gates_client.go,hosts_client.go,listener.go,listener_unsupported.go,network_endpoints.go,qualification_client.go,qualification_producer.go,restore_client.go,schedule_client.go": {imports: []string{"bytes", "context", "crypto/sha256", "encoding/hex", "encoding/json", "errors", "github.com/vegastack/vegastack-labs/internal/credentialref", "github.com/vegastack/vegastack-labs/internal/failure", "github.com/vegastack/vegastack-labs/internal/generated", "github.com/vegastack/vegastack-labs/internal/hostaction", "github.com/vegastack/vegastack-labs/internal/localtransport", "github.com/vegastack/vegastack-labs/internal/networkconnect", "github.com/vegastack/vegastack-labs/internal/principal", "github.com/vegastack/vegastack-labs/internal/result", "github.com/vegastack/vegastack-labs/internal/runprotocol", "github.com/vegastack/vegastack-labs/internal/serverconfig", "github.com/vegastack/vegastack-labs/internal/sshtransport", "io", "mime", "net", "runtime", "strconv", "strings", "sync", "time"}, digest: "07b09d36f7145790afddffae53631d2b7463b0e794a73b35a354c7148b8733b6"},
	"internal/networkconnect|client.go,endpoint.go,private_key_windows.go": {imports: []string{"context", "crypto/sha256", "crypto/tls", "encoding/hex", "encoding/json", "github.com/vegastack/vegastack-labs/internal/failure", "github.com/vegastack/vegastack-labs/internal/generated", "golang.org/x/crypto/ssh", "io", "net", "net/http", "net/netip", "net/url", "regexp", "strconv", "strings", "time"}, digest: "cffd4025eb273e5f1c0a8141222b8a58ff567b6c55f5a300bc667c51cfd83a19"},
	"internal/serverconfig|profile.go,profile_unsupported.go,restic.go":    {imports: []string{"bytes", "context", "encoding/hex", "encoding/json", "github.com/vegastack/vegastack-labs/internal/backupidentity", "github.com/vegastack/vegastack-labs/internal/failure", "github.com/vegastack/vegastack-labs/internal/generated", "github.com/vegastack/vegastack-labs/internal/principal", "io", "io/fs", "net/netip", "net/url", "path/filepath", "regexp", "strings", "time"}, digest: "9ed86a32fbf39cb42e0ec1dc2d39ba7ec61d56f17275edd684f2debb8be2eba4"},
}

func approvedNetworkConnectPackage(c checkedSourcePackage, module, relative string) bool {
	if c.listed.ImportPath != module+"/"+relative || len(c.listed.CgoFiles) != 0 {
		return false
	}
	names := append([]string(nil), c.listed.GoFiles...)
	slices.Sort(names)
	key := relative + "|" + strings.Join(names, ",")
	for _, seals := range []map[string]hostActionSourceSeal{websiteDeliverySourceSeals, phase10SourceSeals, ingressPilotSourceSeals, ciDeliverySourceSeals, ciNetworkSourceSeals, ciJobSourceSeals, ciEnrollmentSourceSeals, networkConnectSourceSeals, combinedNetworkSourceSeals, serviceCatalogSourceSeals, serviceDeploymentSourceSeals, phase8FinishSourceSeals} {
		seal, ok := seals[key]
		if !ok {
			continue
		}
		imports := append([]string(nil), c.listed.Imports...)
		slices.Sort(imports)
		expected := append([]string(nil), seal.imports...)
		for i, v := range expected {
			expected[i] = strings.Replace(v, "github.com/vegastack/vegastack-labs/", module+"/", 1)
		}
		slices.Sort(expected)
		if slices.Equal(imports, expected) && digestSourceFiles(c.listed.Dir, names) == seal.digest {
			return true
		}
	}
	return false
}
