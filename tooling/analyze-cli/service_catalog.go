package main

import (
	"slices"
	"strings"
)

// #286 admits only the exact typed service client and protected profile variants.
// Earlier source seals remain historical and unchanged.
var serviceCatalogSourceSeals = map[string]hostActionSourceSeal{
	"internal/localapi|apply_bound.go,approval_client.go,audit_client.go,authorization_grants.go,backup_client.go,client.go,credential_client.go,credential_lifecycle_client.go,database_client.go,gates_client.go,hosts_client.go,ingress_client.go,listener.go,listener_linux.go,mesh_client.go,network_endpoints.go,qualification_client.go,qualification_producer.go,restore_client.go,schedule_client.go,services_client.go": {imports: []string{"bytes", "context", "crypto/sha256", "encoding/hex", "encoding/json", "errors", "github.com/vegastack/vegastack-labs/internal/credentialref", "github.com/vegastack/vegastack-labs/internal/failure", "github.com/vegastack/vegastack-labs/internal/generated", "github.com/vegastack/vegastack-labs/internal/hostaction", "github.com/vegastack/vegastack-labs/internal/localtransport", "github.com/vegastack/vegastack-labs/internal/networkconnect", "github.com/vegastack/vegastack-labs/internal/principal", "github.com/vegastack/vegastack-labs/internal/result", "github.com/vegastack/vegastack-labs/internal/runprotocol", "github.com/vegastack/vegastack-labs/internal/serverconfig", "github.com/vegastack/vegastack-labs/internal/servicecatalog", "github.com/vegastack/vegastack-labs/internal/sshtransport", "golang.org/x/sys/unix", "io", "mime", "net", "net/url", "os", "path/filepath", "runtime", "strconv", "strings", "sync", "time"}, digest: "eab3d0c8f4e358eb7ef33fb7b3a4fbca081f679642e0c8f5c39f4370a464a592"},
	"internal/serverconfig|profile.go,profile_linux.go,restic.go,service_bindings.go": {imports: []string{"bytes", "context", "crypto/sha256", "encoding/hex", "encoding/json", "github.com/vegastack/vegastack-labs/internal/backupidentity", "github.com/vegastack/vegastack-labs/internal/failure", "github.com/vegastack/vegastack-labs/internal/generated", "github.com/vegastack/vegastack-labs/internal/principal", "golang.org/x/sys/unix", "io", "io/fs", "net/netip", "net/url", "os", "path/filepath", "regexp", "runtime", "strings", "time"}, digest: "b570cf74842c0a170f6c1def1441600838c19d54561828c8faf6f8143a3aaee6"},
	"internal/localapi|apply_bound.go,approval_client.go,audit_client.go,authorization_grants.go,backup_client.go,client.go,credential_client.go,credential_lifecycle_client.go,database_client.go,gates_client.go,hosts_client.go,ingress_client.go,listener.go,listener_unsupported.go,mesh_client.go,network_endpoints.go,qualification_client.go,qualification_producer.go,restore_client.go,schedule_client.go,services_client.go": {imports: []string{"bytes", "context", "crypto/sha256", "encoding/hex", "encoding/json", "errors", "github.com/vegastack/vegastack-labs/internal/credentialref", "github.com/vegastack/vegastack-labs/internal/failure", "github.com/vegastack/vegastack-labs/internal/generated", "github.com/vegastack/vegastack-labs/internal/hostaction", "github.com/vegastack/vegastack-labs/internal/localtransport", "github.com/vegastack/vegastack-labs/internal/networkconnect", "github.com/vegastack/vegastack-labs/internal/principal", "github.com/vegastack/vegastack-labs/internal/result", "github.com/vegastack/vegastack-labs/internal/runprotocol", "github.com/vegastack/vegastack-labs/internal/serverconfig", "github.com/vegastack/vegastack-labs/internal/servicecatalog", "github.com/vegastack/vegastack-labs/internal/sshtransport", "io", "mime", "net", "net/url", "runtime", "strconv", "strings", "sync", "time"}, digest: "1e08ded28cf4281838543436b82e4d6661179ea8ac063d10b9fb00de9354029a"},
	"internal/serverconfig|profile.go,profile_unsupported.go,restic.go,service_bindings.go": {imports: []string{"bytes", "context", "encoding/hex", "encoding/json", "github.com/vegastack/vegastack-labs/internal/backupidentity", "github.com/vegastack/vegastack-labs/internal/failure", "github.com/vegastack/vegastack-labs/internal/generated", "github.com/vegastack/vegastack-labs/internal/principal", "io", "io/fs", "net/netip", "net/url", "path/filepath", "regexp", "strings", "time"}, digest: "0a6c3e784c7efa768e1078ddf9459e7771f185193e9c0d08147a9ead3448f4dc"},
	"internal/servicecatalog|types.go": {imports: []string{"encoding/json", "github.com/vegastack/vegastack-labs/internal/failure", "github.com/vegastack/vegastack-labs/internal/generated", "github.com/vegastack/vegastack-labs/internal/hostaction"}, digest: "d5045be4ee1f13999faaa0c6d71fea610b00e87503e070a4d7993f53907ae9fb"},
}

// Only this exact wave may use the pure query parser and intent validator.
func approvedServiceCatalogPackage(c checkedSourcePackage, module, relative string) bool {
	if c.listed.ImportPath != module+"/"+relative || len(c.listed.CgoFiles) != 0 {
		return false
	}
	names := slices.Clone(c.listed.GoFiles)
	slices.Sort(names)
	seal, ok := serviceCatalogSourceSeals[relative+"|"+strings.Join(names, ",")]
	if !ok {
		return false
	}
	imports := slices.Clone(c.listed.Imports)
	slices.Sort(imports)
	expected := slices.Clone(seal.imports)
	for i, v := range expected {
		expected[i] = strings.Replace(v, "github.com/vegastack/vegastack-labs/", module+"/", 1)
	}
	slices.Sort(expected)
	return slices.Equal(imports, expected) && digestSourceFiles(c.listed.Dir, names) == seal.digest
}
