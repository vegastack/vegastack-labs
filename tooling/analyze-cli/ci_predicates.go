package main

import (
	"crypto/sha256"
	"fmt"
	"go/ast"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// These two records query current persisted human/actor grants. They dispatch
// no operation. Permit only this exact literal in the sealed CI execution file.
func reviewedCIJobGrantPredicates(candidate checkedSourcePackage, file *ast.File, literal *ast.CompositeLit, generatedImport string) bool {
	if reviewedCIJobPreparationPredicates(candidate, file, literal, generatedImport) {
		return true
	}
	if candidate.listed.ImportPath != strings.TrimSuffix(generatedImport, "/internal/generated")+"/internal/store" {
		return false
	}
	names := append(append([]string(nil), candidate.listed.GoFiles...), candidate.listed.CgoFiles...)
	sort.Strings(names)
	owner := false
	for i, parsed := range candidate.files {
		if parsed == file && i < len(names) && names[i] == "ci_job_execution.go" {
			owner = true
		}
	}
	if !owner {
		return false
	}
	raw, e := os.ReadFile(filepath.Join(candidate.listed.Dir, "ci_job_execution.go"))
	if e != nil || (fmt.Sprintf("%x", sha256.Sum256(raw)) != "06322e37edf0c78139e05be7a83d412621f928671ba0b684e6f33b4e2061a8af" && fmt.Sprintf("%x", sha256.Sum256(raw)) != "44880c2c5ee356aee780aa999327755ea672413d281c2e3d24c90495a5713639") {
		return false
	}
	array, ok := literal.Type.(*ast.ArrayType)
	if !ok || array.Len != nil || len(literal.Elts) != 2 {
		return false
	}
	record, ok := array.Elt.(*ast.StructType)
	if !ok || record.Fields == nil || len(record.Fields.List) != 2 {
		return false
	}
	fields := record.Fields.List
	if !ciPredicateFields(fields[0], []string{"id", "action", "cap", "kind"}, "string") || !ciPredicateFields(fields[1], []string{"admin"}, "bool") {
		return false
	}
	for i, row := range literal.Elts {
		values, ok := row.(*ast.CompositeLit)
		if !ok || values.Type != nil || len(values.Elts) != 5 {
			return false
		}
		if i == 0 {
			selector, ok := values.Elts[0].(*ast.SelectorExpr)
			if !ok || selector.Sel.Name != "ID" || !ciPredicateIdent(selector.X, "actor") || ciPredicateString(values.Elts[1]) != "execute" || !ciPredicateIdent(values.Elts[2], "CIJobOperation") || ciPredicateString(values.Elts[3]) != "execution-target" {
				return false
			}
		} else if !ciPredicateIdent(values.Elts[0], "human") || ciPredicateString(values.Elts[1]) != "acknowledge" || ciPredicateString(values.Elts[2]) != "plan.acknowledge" || ciPredicateString(values.Elts[3]) != "plan-target" {
			return false
		}
		if !ciPredicateIdent(values.Elts[4], "true") {
			return false
		}
	}
	for _, d := range file.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "currentExecutionTx" || fn.Body == nil {
			continue
		}
		found := false
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if r, ok := n.(*ast.RangeStmt); ok && r.X == literal {
				found = true
			}
			return !found
		})
		return found
	}
	return false
}
func ciPredicateIdent(expr ast.Expr, name string) bool {
	id, ok := expr.(*ast.Ident)
	return ok && id.Name == name
}
func ciPredicateFields(field *ast.Field, names []string, kind string) bool {
	if len(field.Names) != len(names) || !ciPredicateIdent(field.Type, kind) || field.Tag != nil {
		return false
	}
	for i, n := range field.Names {
		if n.Name != names[i] {
			return false
		}
	}
	return true
}

func ciPredicateString(expr ast.Expr) string {
	literal, ok := expr.(*ast.BasicLit)
	if !ok || literal.Kind != token.STRING {
		return ""
	}
	value, e := strconv.Unquote(literal.Value)
	if e != nil {
		return ""
	}
	return value
}

// The preparation checks are exactly three current grant queries, not command
// dispatch records. This independent seal does not widen the execution seal.
func reviewedCIJobPreparationPredicates(candidate checkedSourcePackage, file *ast.File, literal *ast.CompositeLit, generatedImport string) bool {
	if candidate.listed.ImportPath != strings.TrimSuffix(generatedImport, "/internal/generated")+"/internal/store" {
		return false
	}
	names := append(append([]string(nil), candidate.listed.GoFiles...), candidate.listed.CgoFiles...)
	sort.Strings(names)
	owner := false
	for i, parsed := range candidate.files {
		if parsed == file && i < len(names) && names[i] == "ci_job.go" {
			owner = true
		}
	}
	if !owner {
		return false
	}
	raw, e := os.ReadFile(filepath.Join(candidate.listed.Dir, "ci_job.go"))
	if e != nil || (fmt.Sprintf("%x", sha256.Sum256(raw)) != "0299c1b8c621ae4ed7599da272abb3597c975c1b861c3049c6e6c82d2c4e5e99" && fmt.Sprintf("%x", sha256.Sum256(raw)) != "05ca306edabb0c00ecd7e2102811ac8aab01d37c2ed134dd547f03c9a99bd09f") {
		return false
	}
	array, ok := literal.Type.(*ast.ArrayType)
	if !ok || array.Len != nil || len(literal.Elts) != 3 {
		return false
	}
	record, ok := array.Elt.(*ast.StructType)
	if !ok || record.Fields == nil || len(record.Fields.List) != 2 {
		return false
	}
	if !ciPredicateFields(record.Fields.List[0], []string{"id", "kind", "action", "cap"}, "string") || !ciPredicateFields(record.Fields.List[1], []string{"admin"}, "bool") {
		return false
	}
	for i, row := range literal.Elts {
		values, ok := row.(*ast.CompositeLit)
		if !ok || values.Type != nil || len(values.Elts) != 5 {
			return false
		}
		if i == 0 {
			if !ciPredicateSelector(values.Elts[0], "in", "Definition", "EnrollmentID") || ciPredicateString(values.Elts[1]) != "ci-enrollment" || ciPredicateString(values.Elts[2]) != "author" || ciPredicateString(values.Elts[3]) != "ci.job.prepare" || !ciPredicateIdent(values.Elts[4], "false") {
				return false
			}
		} else {
			action, capability, admin := "read", "host.read", "false"
			if i == 2 {
				action, capability, admin = "author", "host.action.prepare", "true"
			}
			if !ciPredicateSelector(values.Elts[0], "in", "HostID") || ciPredicateString(values.Elts[1]) != "host" || ciPredicateString(values.Elts[2]) != action || ciPredicateString(values.Elts[3]) != capability || !ciPredicateIdent(values.Elts[4], admin) {
				return false
			}
		}
	}
	for _, d := range file.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "validate" || fn.Body == nil {
			continue
		}
		found := false
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if r, ok := n.(*ast.RangeStmt); ok && r.X == literal {
				found = true
			}
			return !found
		})
		return found
	}
	return false
}
func ciPredicateSelector(expr ast.Expr, path ...string) bool {
	if len(path) == 1 {
		return ciPredicateIdent(expr, path[0])
	}
	selector, ok := expr.(*ast.SelectorExpr)
	return ok && selector.Sel.Name == path[len(path)-1] && ciPredicateSelector(selector.X, path[:len(path)-1]...)
}
