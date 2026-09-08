// Command analyze-server performs syntax-tree checks for the local control-service boundary.
package main

import (
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
			if importPath == "database/sql" {
				result.SQLiteAccess = true
			}
			if importPath == "golang.org/x/sys/unix" && !(strings.HasSuffix(relative, "_linux.go") && (strings.HasPrefix(relative, "internal/localapi/") || strings.HasPrefix(relative, "internal/serverconfig/"))) {
				result.XSysOutsideScope = true
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
				if len(call.Args) == 0 || stringLiteral(call.Args[0]) != "unix" {
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
	for directory := range mainDirectories {
		result.ExecutableDirectories = append(result.ExecutableDirectories, directory)
	}
	source := serverSource.String()
	result.PlatformScopeInvalid = !(strings.Contains(source, `"linux"`) && strings.Contains(source, `"amd64"`) && strings.Contains(source, `"debian"`) && (strings.Contains(source, "Major == 13") || strings.Contains(source, "major == 13") || strings.Contains(source, "major != 13")))
	return result, nil
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
