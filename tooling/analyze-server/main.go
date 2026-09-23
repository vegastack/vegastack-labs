// Command analyze-server performs syntax-tree checks for the local control-service boundary.
package main

import (
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type analysis struct {
	ExecutableDirectories []string `json:"executableDirectories"`
	TCPListener           bool     `json:"tcpListener"`
	IdentityHeaderTrust   bool     `json:"identityHeaderTrust"`
	ContextSetterOutside  bool     `json:"contextSetterOutside"`
	SQLiteAccess          bool     `json:"sqliteAccess"`
	XSysOutsideScope      bool     `json:"xSysOutsideScope"`
	PlatformScopeInvalid  bool     `json:"platformScopeInvalid"`
}

func main() {
	root := flag.String("root", "", "repository root")
	flag.Parse()
	if *root == "" {
		fmt.Fprintln(os.Stderr, "analyze-server: --root is required")
		os.Exit(2)
	}
	result, err := analyze(*root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "analyze-server: source analysis failed")
		os.Exit(1)
	}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		os.Exit(1)
	}
}

func analyze(root string) (analysis, error) {
	var result analysis
	mainDirectories := make(map[string]bool)
	serverSource := strings.Builder{}
	remoteListenerPresent := false
	approvedRemoteTCP := make(map[token.Pos]bool)
	err := filepath.WalkDir(root, func(filename string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			name := entry.Name()
			if name == ".git" || name == "node_modules" || name == ".next" || name == "out" || (filename != root && strings.HasPrefix(name, ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(filename, ".go") || strings.HasSuffix(filename, "_test.go") {
			return nil
		}
		relative, err := filepath.Rel(root, filename)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if !(strings.HasPrefix(relative, "cmd/") || strings.HasPrefix(relative, "internal/")) {
			return nil
		}
		fileSet := token.NewFileSet()
		file, err := parser.ParseFile(fileSet, filename, nil, 0)
		if err != nil {
			return err
		}
		content, err := os.ReadFile(filename)
		if err != nil {
			return err
		}
		if strings.HasPrefix(relative, "cmd/") && file.Name.Name == "main" {
			mainDirectories[filepath.ToSlash(filepath.Dir(relative))] = true
		}
		isServer := strings.HasPrefix(relative, "internal/server/")
		isReviewedRemoteListener := relative == "internal/server/remote.go"
		importAliases := make(map[string]string)
		if isServer {
			serverSource.Write(content)
		}
		for _, imported := range file.Imports {
			importPath, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				return err
			}
			name := filepath.Base(importPath)
			if imported.Name != nil {
				name = imported.Name.Name
			}
			if name != "_" && name != "." {
				importAliases[name] = importPath
			}
			if importPath == "database/sql" && !strings.HasPrefix(relative, "internal/store/") {
				result.SQLiteAccess = true
			}
			approvedClientFile := relative == "internal/clientfile/read_unix.go"
			approvedNativeCredentialFile := relative == "internal/adapter/nativecredential/lifecycle_verifier_linux.go" || relative == "internal/adapter/nativecredential/process_observer_linux.go" || relative == "internal/adapter/nativecredential/authority_linux.go" || relative == "internal/adapter/nativecredential/probe_linux.go" || relative == "internal/adapter/nativecredential/encrypt_linux.go" || relative == "internal/adapter/nativecredential/inspect_linux.go" || relative == "internal/adapter/nativecredential/resolver_linux.go"
			approvedLinuxFile := strings.HasSuffix(relative, "_linux.go") && (approvedNativeCredentialFile || strings.HasPrefix(relative, "internal/backup/") || strings.HasPrefix(relative, "internal/identity/") || strings.HasPrefix(relative, "internal/localapi/") || relative == "internal/server/credential_resolver_linux.go" || relative == "internal/server/remote_tls_linux.go" || relative == "internal/server/slack_acknowledgement_config_linux.go" || relative == "internal/server/systemd_credentials_linux.go" || strings.HasPrefix(relative, "internal/serverconfig/") || strings.HasPrefix(relative, "internal/store/"))
			// #106's guarded local adapter and #146's exact protected recovery
			// files are separate reviewed Unix file-descriptor scopes.
			approvedBackupAdapterFile := relative == "internal/adapter/localbackup/adapter.go"
			if importPath == "golang.org/x/sys/unix" && !(approvedClientFile || approvedLinuxFile || approvedBackupAdapterFile || reviewedRecoveryUnixFile(relative, content)) {
				result.XSysOutsideScope = true
			}
		}
		if isReviewedRemoteListener {
			remoteListenerPresent = true
			if position, ok := reviewedRemoteListener(file, importAliases); ok {
				approvedRemoteTCP[position] = true
			}
		}
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			importPath := selectorImportPath(selector, importAliases)
			switch {
			case importPath == "net" && selector.Sel.Name == "ListenTCP":
				result.TCPListener = true
			case importPath == "net/http" && (selector.Sel.Name == "ListenAndServe" || selector.Sel.Name == "ListenAndServeTLS"):
				result.TCPListener = true
			case importPath == "net" && selector.Sel.Name == "Listen":
				if len(call.Args) == 0 || (stringLiteral(call.Args[0]) != "unix" && !approvedRemoteTCP[call.Pos()]) {
					result.TCPListener = true
				}
			case selector.Sel.Name == "Listen" && importPath == "":
				if len(call.Args) < 2 || stringLiteral(call.Args[1]) != "tcp" || !approvedRemoteTCP[call.Pos()] {
					result.TCPListener = true
				}
			case strings.HasSuffix(importPath, "/internal/identity") && selector.Sel.Name == "WithVerifiedPrincipal":
				if !isServer {
					result.ContextSetterOutside = true
				}
			case selector.Sel.Name == "Get" || selector.Sel.Name == "Values":
				if !isServer && isHeaderSelector(selector.X) && len(call.Args) > 0 && identityHeader(stringLiteral(call.Args[0])) {
					result.IdentityHeaderTrust = true
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		return analysis{}, err
	}
	if remoteListenerPresent && len(approvedRemoteTCP) != 1 {
		result.TCPListener = true
	}
	for directory := range mainDirectories {
		result.ExecutableDirectories = append(result.ExecutableDirectories, directory)
	}
	source := serverSource.String()
	result.PlatformScopeInvalid = !(strings.Contains(source, `"linux"`) && strings.Contains(source, `"amd64"`) && strings.Contains(source, `"debian"`) && (strings.Contains(source, "Major == 13") || strings.Contains(source, "major == 13") || strings.Contains(source, "major != 13")))
	return result, nil
}

// These custody paths use no-follow Unix file descriptors for one protected
// manifest, one durable receipt and one fixed systemd-loaded recipient key.
// No other recovery source gains a blanket x/sys/unix exception.
func reviewedRecoveryUnixFile(relative string, content []byte) bool {
	var expected string
	switch relative {
	case "internal/recovery/manifest_file_unix.go":
		expected = "c037f299077084fb66ed6fa660e9a434732ecc006c5d986982b4bea538cdbebe"
	case "internal/recovery/receipt_file_unix.go":
		expected = "87b5ac429e13b1631a7d9c17160d1b6978b1bbb66626e714b463de97befcac3c"
	case "internal/server/recovery_recipient_linux.go":
		expected = "1bb55d15e07c13baddab7e1933f56e767179ddf01ba0bc42dca76aa710b5e10e"
	default:
		return false
	}
	sum := sha256.Sum256(content)
	return fmt.Sprintf("%x", sum) == expected
}

func reviewedRemoteListener(file *ast.File, aliases map[string]string) (token.Pos, bool) {
	var function *ast.FuncDecl
	for _, declaration := range file.Decls {
		candidate, ok := declaration.(*ast.FuncDecl)
		if ok && candidate.Recv == nil && candidate.Name.Name == "RemoteListen" {
			if function != nil {
				return 0, false
			}
			function = candidate
		}
	}
	if function == nil || function.Body == nil {
		return 0, false
	}
	var tcpCalls, tlsListeners []*ast.CallExpr
	var listenerName, certificateName, configName string
	configValid := false
	ast.Inspect(function.Body, func(node ast.Node) bool {
		if call, ok := node.(*ast.CallExpr); ok {
			selector, selectorOK := call.Fun.(*ast.SelectorExpr)
			if selectorOK && selector.Sel.Name == "Listen" && len(call.Args) >= 2 && stringLiteral(call.Args[1]) == "tcp" {
				tcpCalls = append(tcpCalls, call)
			}
			if selectorOK && selectorImportPath(selector, aliases) == "crypto/tls" && selector.Sel.Name == "NewListener" {
				tlsListeners = append(tlsListeners, call)
			}
		}
		assignment, ok := node.(*ast.AssignStmt)
		if !ok || len(assignment.Lhs) == 0 || len(assignment.Rhs) == 0 {
			return true
		}
		left, ok := assignment.Lhs[0].(*ast.Ident)
		if !ok {
			return true
		}
		if call, ok := assignment.Rhs[0].(*ast.CallExpr); ok {
			if identifier, ok := call.Fun.(*ast.Ident); ok && identifier.Name == "loadProtectedTLSKeyPair" {
				certificateName = left.Name
			}
			if selector, ok := call.Fun.(*ast.SelectorExpr); ok && selector.Sel.Name == "Listen" && len(call.Args) >= 2 && stringLiteral(call.Args[1]) == "tcp" {
				listenerName = left.Name
			}
		}
		if composite := tlsConfigLiteral(assignment.Rhs[0], aliases); composite != nil {
			configName = left.Name
			configValid = validTLS13Config(composite, aliases, certificateName)
		}
		return true
	})
	if len(tcpCalls) != 1 || len(tlsListeners) != 1 || listenerName == "" || certificateName == "" || configName == "" || !configValid {
		return 0, false
	}
	tlsCall := tlsListeners[0]
	if len(tlsCall.Args) != 2 || identifierName(tlsCall.Args[0]) != listenerName || identifierName(tlsCall.Args[1]) != configName || !callReturned(function.Body, tlsCall) {
		return 0, false
	}
	return tcpCalls[0].Pos(), true
}

func tlsConfigLiteral(expression ast.Expr, aliases map[string]string) *ast.CompositeLit {
	if unary, ok := expression.(*ast.UnaryExpr); ok && unary.Op == token.AND {
		expression = unary.X
	}
	composite, ok := expression.(*ast.CompositeLit)
	if !ok {
		return nil
	}
	selector, ok := composite.Type.(*ast.SelectorExpr)
	if !ok || selectorImportPath(selector, aliases) != "crypto/tls" || selector.Sel.Name != "Config" {
		return nil
	}
	return composite
}

func validTLS13Config(config *ast.CompositeLit, aliases map[string]string, certificateName string) bool {
	fields := make(map[string]ast.Expr)
	for _, element := range config.Elts {
		pair, ok := element.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		if key, ok := pair.Key.(*ast.Ident); ok {
			fields[key.Name] = pair.Value
		}
	}
	for _, name := range []string{"MinVersion", "MaxVersion"} {
		selector, ok := fields[name].(*ast.SelectorExpr)
		if !ok || selectorImportPath(selector, aliases) != "crypto/tls" || selector.Sel.Name != "VersionTLS13" {
			return false
		}
	}
	certificates := fields["Certificates"]
	foundCertificate := false
	ast.Inspect(certificates, func(node ast.Node) bool {
		if identifier, ok := node.(*ast.Ident); ok && identifier.Name == certificateName {
			foundCertificate = true
		}
		return true
	})
	return foundCertificate
}

func callReturned(body *ast.BlockStmt, target *ast.CallExpr) bool {
	found := false
	ast.Inspect(body, func(node ast.Node) bool {
		statement, ok := node.(*ast.ReturnStmt)
		if !ok {
			return true
		}
		for _, result := range statement.Results {
			ast.Inspect(result, func(candidate ast.Node) bool {
				if candidate == target {
					found = true
					return false
				}
				return true
			})
		}
		return true
	})
	return found
}

func identifierName(expression ast.Expr) string {
	identifier, _ := expression.(*ast.Ident)
	if identifier == nil {
		return ""
	}
	return identifier.Name
}

func selectorImportPath(selector *ast.SelectorExpr, aliases map[string]string) string {
	identifier, ok := selector.X.(*ast.Ident)
	if !ok {
		return ""
	}
	return aliases[identifier.Name]
}

func isHeaderSelector(expression ast.Expr) bool {
	selector, ok := expression.(*ast.SelectorExpr)
	return ok && selector.Sel.Name == "Header"
}

func stringLiteral(expression ast.Expr) string {
	literal, ok := expression.(*ast.BasicLit)
	if !ok || literal.Kind != token.STRING {
		return ""
	}
	value, _ := strconv.Unquote(literal.Value)
	return value
}

func identityHeader(value string) bool {
	switch strings.ToLower(value) {
	case "x-vsk-principal", "x-vsk-uid", "x-vsk-gid", "x-vsk-role":
		return true
	default:
		return false
	}
}
