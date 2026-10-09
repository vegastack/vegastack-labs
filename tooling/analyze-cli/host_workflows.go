package main

import (
	"slices"
	"strings"
)

// #239 extends only the exact typed host workflow client source closures.
// Historical #230 and #233 seals remain unchanged.
var hostWorkflowSourceSeals = map[string]hostActionSourceSeal{
	"internal/localapi|audit_client.go,backup_client.go,client.go,credential_client.go,credential_lifecycle_client.go,database_client.go,gates_client.go,hosts_client.go,listener.go,listener_linux.go,restore_client.go,schedule_client.go":       {imports: []string{"bytes", "context", "crypto/sha256", "encoding/hex", "encoding/json", "errors", "github.com/vegastack/vegastack-labs/internal/credentialref", "github.com/vegastack/vegastack-labs/internal/failure", "github.com/vegastack/vegastack-labs/internal/generated", "github.com/vegastack/vegastack-labs/internal/localtransport", "github.com/vegastack/vegastack-labs/internal/principal", "github.com/vegastack/vegastack-labs/internal/result", "github.com/vegastack/vegastack-labs/internal/runprotocol", "github.com/vegastack/vegastack-labs/internal/serverconfig", "github.com/vegastack/vegastack-labs/internal/sshtransport", "golang.org/x/sys/unix", "io", "mime", "net", "os", "path/filepath", "runtime", "strconv", "strings", "sync", "time"}, digest: "d6f409f53d572981d35fd2918a82e809a9b228cb92158fb1aecd144f91ecb85e"},
	"internal/localapi|audit_client.go,backup_client.go,client.go,credential_client.go,credential_lifecycle_client.go,database_client.go,gates_client.go,hosts_client.go,listener.go,listener_unsupported.go,restore_client.go,schedule_client.go": {imports: []string{"bytes", "context", "crypto/sha256", "encoding/hex", "encoding/json", "errors", "github.com/vegastack/vegastack-labs/internal/credentialref", "github.com/vegastack/vegastack-labs/internal/failure", "github.com/vegastack/vegastack-labs/internal/generated", "github.com/vegastack/vegastack-labs/internal/localtransport", "github.com/vegastack/vegastack-labs/internal/principal", "github.com/vegastack/vegastack-labs/internal/result", "github.com/vegastack/vegastack-labs/internal/runprotocol", "github.com/vegastack/vegastack-labs/internal/serverconfig", "github.com/vegastack/vegastack-labs/internal/sshtransport", "io", "mime", "net", "runtime", "strconv", "strings", "sync", "time"}, digest: "f567efec8e5c529e603b50593a77f15f38fe88db695e5861a443b5e71a74009d"},
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
