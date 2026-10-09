package main

import (
	"slices"
	"strings"
)

// #239 extends only the exact typed host workflow client source closures.
// Historical #230 and #233 seals remain unchanged.
var hostWorkflowSourceSeals = map[string]hostActionSourceSeal{
	// #247 adds only the typed inert grant draft, with the same portable imports.
	"internal/localapi|audit_client.go,authorization_grants.go,backup_client.go,client.go,credential_client.go,credential_lifecycle_client.go,database_client.go,gates_client.go,hosts_client.go,listener.go,listener_linux.go,restore_client.go,schedule_client.go":       {imports: []string{"bytes", "context", "crypto/sha256", "encoding/hex", "encoding/json", "errors", "github.com/vegastack/vegastack-labs/internal/credentialref", "github.com/vegastack/vegastack-labs/internal/failure", "github.com/vegastack/vegastack-labs/internal/generated", "github.com/vegastack/vegastack-labs/internal/localtransport", "github.com/vegastack/vegastack-labs/internal/principal", "github.com/vegastack/vegastack-labs/internal/result", "github.com/vegastack/vegastack-labs/internal/runprotocol", "github.com/vegastack/vegastack-labs/internal/serverconfig", "github.com/vegastack/vegastack-labs/internal/sshtransport", "golang.org/x/sys/unix", "io", "mime", "net", "os", "path/filepath", "runtime", "strconv", "strings", "sync", "time"}, digest: "38ba6037daca76c281a48f5a54104f91841acdf0511e39251839eacaee1d5208"},
	"internal/localapi|audit_client.go,authorization_grants.go,backup_client.go,client.go,credential_client.go,credential_lifecycle_client.go,database_client.go,gates_client.go,hosts_client.go,listener.go,listener_unsupported.go,restore_client.go,schedule_client.go": {imports: []string{"bytes", "context", "crypto/sha256", "encoding/hex", "encoding/json", "errors", "github.com/vegastack/vegastack-labs/internal/credentialref", "github.com/vegastack/vegastack-labs/internal/failure", "github.com/vegastack/vegastack-labs/internal/generated", "github.com/vegastack/vegastack-labs/internal/localtransport", "github.com/vegastack/vegastack-labs/internal/principal", "github.com/vegastack/vegastack-labs/internal/result", "github.com/vegastack/vegastack-labs/internal/runprotocol", "github.com/vegastack/vegastack-labs/internal/serverconfig", "github.com/vegastack/vegastack-labs/internal/sshtransport", "io", "mime", "net", "runtime", "strconv", "strings", "sync", "time"}, digest: "f970ccaba7e1389182ed47d5f13e6d1b0b927aa50aa1c1141150cd9206b0735b"},

	"internal/localapi|audit_client.go,backup_client.go,client.go,credential_client.go,credential_lifecycle_client.go,database_client.go,gates_client.go,hosts_client.go,listener.go,listener_linux.go,restore_client.go,schedule_client.go":       {imports: []string{"bytes", "context", "crypto/sha256", "encoding/hex", "encoding/json", "errors", "github.com/vegastack/vegastack-labs/internal/credentialref", "github.com/vegastack/vegastack-labs/internal/failure", "github.com/vegastack/vegastack-labs/internal/generated", "github.com/vegastack/vegastack-labs/internal/localtransport", "github.com/vegastack/vegastack-labs/internal/principal", "github.com/vegastack/vegastack-labs/internal/result", "github.com/vegastack/vegastack-labs/internal/runprotocol", "github.com/vegastack/vegastack-labs/internal/serverconfig", "github.com/vegastack/vegastack-labs/internal/sshtransport", "golang.org/x/sys/unix", "io", "mime", "net", "os", "path/filepath", "runtime", "strconv", "strings", "sync", "time"}, digest: "c13cf7f092c8fff17fc0a61f3917ec26e39d58de9967d1a30dd127aeccb3b1e7"},
	"internal/localapi|audit_client.go,backup_client.go,client.go,credential_client.go,credential_lifecycle_client.go,database_client.go,gates_client.go,hosts_client.go,listener.go,listener_unsupported.go,restore_client.go,schedule_client.go": {imports: []string{"bytes", "context", "crypto/sha256", "encoding/hex", "encoding/json", "errors", "github.com/vegastack/vegastack-labs/internal/credentialref", "github.com/vegastack/vegastack-labs/internal/failure", "github.com/vegastack/vegastack-labs/internal/generated", "github.com/vegastack/vegastack-labs/internal/localtransport", "github.com/vegastack/vegastack-labs/internal/principal", "github.com/vegastack/vegastack-labs/internal/result", "github.com/vegastack/vegastack-labs/internal/runprotocol", "github.com/vegastack/vegastack-labs/internal/serverconfig", "github.com/vegastack/vegastack-labs/internal/sshtransport", "io", "mime", "net", "runtime", "strconv", "strings", "sync", "time"}, digest: "c71c777cd7886630690e9fd82c6087c16060f7e2add8d78ee33618039aaa7577"},
}

func reviewedHostWorkflowPackage(c checkedSourcePackage, module, relative string) bool {
	if c.listed.ImportPath != module+"/"+relative || len(c.listed.CgoFiles) != 0 {
		return false
	}
	names := append([]string(nil), c.listed.GoFiles...)
	slices.Sort(names)
	seal, ok := hostWorkflowSourceSeals[relative+"|"+strings.Join(names, ",")]
	if !ok {
		return false
	}
	imports := append([]string(nil), c.listed.Imports...)
	slices.Sort(imports)
	expected := append([]string(nil), seal.imports...)
	for i, v := range expected {
		expected[i] = strings.Replace(v, "github.com/vegastack/vegastack-labs/", module+"/", 1)
	}
	slices.Sort(expected)
	return slices.Equal(imports, expected) && digestSourceFiles(c.listed.Dir, names) == seal.digest
}
