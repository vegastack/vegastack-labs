package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"go/ast"
	"go/format"
	"go/token"
	"slices"
	"strings"
)

// Exact collector and whole CLI routing source; no other client route inherits local reads.
var controllerPrerequisiteSourceSeals = map[string]hostActionSourceSeal{
	"internal/cli|app.go,authorization_grants.go,backup.go,ci_enrollment.go,ci_job.go,ci_publication.go,credential_lifecycle.go,credentials.go,database.go,doctor.go,gates.go,go_image.go,host_lifecycle.go,hosting_lifecycle.go,hosts.go,ingress.go,maintenance.go,mesh.go,network_connect.go,notification_readiness.go,operations_monitoring.go,parse.go,qualification.go,recovery_fixture_none.go,recovery_witness.go,render.go,restore.go,role_prepare.go,schedule.go,service_configuration.go,service_deployments.go,service_recovery.go,services.go": {imports: []string{"bytes", "context", "encoding/base64", "encoding/json", "errors", "fmt", "github.com/vegastack/vegastack-labs/internal/adapter/recoverydenial", "github.com/vegastack/vegastack-labs/internal/apissh", "github.com/vegastack/vegastack-labs/internal/clientfile", "github.com/vegastack/vegastack-labs/internal/controllerprerequisites", "github.com/vegastack/vegastack-labs/internal/credentialref", "github.com/vegastack/vegastack-labs/internal/failure", "github.com/vegastack/vegastack-labs/internal/generated", "github.com/vegastack/vegastack-labs/internal/linuxrole", "github.com/vegastack/vegastack-labs/internal/localapi", "github.com/vegastack/vegastack-labs/internal/networkconnect", "github.com/vegastack/vegastack-labs/internal/principal", "github.com/vegastack/vegastack-labs/internal/recovery", "github.com/vegastack/vegastack-labs/internal/release", "github.com/vegastack/vegastack-labs/internal/result", "github.com/vegastack/vegastack-labs/internal/strictjson", "io", "os", "regexp", "runtime", "strconv", "strings", "time"}, digest: "edd6237d0893579ba00a870c2a302e2309864a6fe972d95f4ce153f1f93365c0"},
	"internal/controllerprerequisites|collect.go,collect_linux.go,collect_posix.go":       {imports: []string{"context", "crypto/sha256", "crypto/x509", "encoding/hex", "encoding/json", "encoding/pem", "errors", "github.com/vegastack/vegastack-labs/internal/generated", "golang.org/x/sys/unix", "io", "os", "path/filepath", "regexp", "runtime", "strconv", "strings", "syscall", "time"}, digest: "e5590f282642445df05f56ab4c45c97a0dcd14693f8da72b68fc362f7b6157c5"},
	"internal/controllerprerequisites|collect.go,collect_posix.go,collect_unsupported.go": {imports: []string{"context", "crypto/sha256", "crypto/x509", "encoding/hex", "encoding/json", "encoding/pem", "errors", "github.com/vegastack/vegastack-labs/internal/generated", "golang.org/x/sys/unix", "io", "os", "path/filepath", "regexp", "runtime", "strconv", "strings", "syscall", "time"}, digest: "f9fa0c5cb227705f9b23b778fb418bd4ac253593f6d60cc56ac657ca2350a14e"},
	"internal/controllerprerequisites|collect.go,collect_unsupported.go":                  {imports: []string{"context", "github.com/vegastack/vegastack-labs/internal/generated", "regexp", "runtime"}, digest: "8cef29ef54064be8938121de97ac479ab94bdac2cc8ab8c578144b219e05d6b4"},
}

// Both the collector and every CLI routing byte must match, and only CLI may
// import the collector. No optional policy knob or broad doctor exemption.
func controllerPrerequisiteComposition(packages []listedPackage, module string) bool {
	collector, cli := false, false
	for _, p := range packages {
		if p.ImportPath == module+"/internal/controllerprerequisites" {
			collector = controllerPrerequisitePackage(checkedSourcePackage{listed: p}, module, "internal/controllerprerequisites")
		}
		if p.ImportPath == module+"/internal/cli" {
			cli = controllerPrerequisitePackage(checkedSourcePackage{listed: p}, module, "internal/cli")
		}
		for _, imported := range p.Imports {
			if imported == module+"/internal/controllerprerequisites" && p.ImportPath != module+"/internal/cli" {
				return false
			}
		}
	}
	return collector && cli
}
func controllerPrerequisitePackage(c checkedSourcePackage, module, relative string) bool {
	if c.listed.ImportPath != module+"/"+relative || len(c.listed.CgoFiles) != 0 {
		return false
	}
	names := slices.Clone(c.listed.GoFiles)
	slices.Sort(names)
	seal, ok := controllerPrerequisiteSourceSeals[relative+"|"+strings.Join(names, ",")]
	if !ok {
		return false
	}
	imports := slices.Clone(c.listed.Imports)
	slices.Sort(imports)
	expected := make([]string, len(seal.imports))
	for i, p := range seal.imports {
		expected[i] = strings.ReplaceAll(p, "github.com/vegastack/vegastack-labs/", module+"/")
	}
	slices.Sort(expected)
	return slices.Equal(imports, expected) && digestSourceFiles(c.listed.Dir, names) == seal.digest
}

// The only route-shaped data is this exact fixed-path range literal. Whole
// package bytes and owning AST identity are independently bound.
func reviewedControllerPrerequisiteData(c checkedSourcePackage, file *ast.File, node ast.Node, generatedImport string) bool {
	module := strings.TrimSuffix(generatedImport, "/internal/generated")
	if !controllerPrerequisitePackage(c, module, "internal/controllerprerequisites") {
		return false
	}
	literal, ok := node.(*ast.CompositeLit)
	if !ok || len(literal.Elts) != 7 {
		return false
	}
	var printed bytes.Buffer
	if format.Node(&printed, token.NewFileSet(), literal) != nil {
		return false
	}
	if fmt.Sprintf("%x", sha256.Sum256(printed.Bytes())) != controllerPrerequisiteLiteralDigest {
		return false
	}
	for _, d := range file.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "collectRoot" || fn.Body == nil {
			continue
		}
		found := false
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if r, ok := n.(*ast.RangeStmt); ok && r.X == literal {
				found = true
			}
			return !found
		})
		if found {
			return true
		}
	}
	return false
}

const controllerPrerequisiteLiteralDigest = "71725f73807ed312d5a7f820ee6d4599022a859dcf87ee558336b9098de618b4"
