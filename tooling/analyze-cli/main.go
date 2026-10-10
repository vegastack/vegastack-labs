// Command analyze-cli performs the AST and type-based source checks used by
// tooling/verify-cli.mjs. It is development tooling and is not shipped.
package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type module struct {
	Path string
	Main bool
}

type listedPackage struct {
	ImportPath string
	Dir        string
	GoFiles    []string
	CgoFiles   []string
	Imports    []string
	Export     string
	Module     *module
	Standard   bool
}

type analysis struct {
	GeneratedCommandsReference   bool     `json:"generatedCommandsReference"`
	GeneratedEndpointsReference  bool     `json:"generatedEndpointsReference"`
	HandwrittenRegistry          bool     `json:"handwrittenRegistry"`
	ReleaseArtifactExecution     bool     `json:"releaseArtifactExecution"`
	ReleaseNetworkAccess         bool     `json:"releaseNetworkAccess"`
	SQLiteAccess                 bool     `json:"sqliteAccess"`
	ShellDispatch                bool     `json:"shellDispatch"`
	StateExportTrust             bool     `json:"stateExportTrust"`
	StateExportReleaseCoupling   bool     `json:"stateExportReleaseCoupling"`
	ControlSQLiteAccess          bool     `json:"controlSQLiteAccess"`
	ControlShellDispatch         bool     `json:"controlShellDispatch"`
	ControlGoogleAccess          bool     `json:"controlGoogleAccess"`
	ControlProviderAccess        bool     `json:"controlProviderAccess"`
	ControlArbitraryHTTP         bool     `json:"controlArbitraryHTTP"`
	ControlServerPath            bool     `json:"controlServerPath"`
	InventoryDirectDomain        bool     `json:"inventoryDirectDomain"`
	LocalClientBoundary          bool     `json:"localClientBoundary"`
	RestoreCommandClosureInvalid bool     `json:"restoreCommandClosureInvalid"`
	TargetsAnalyzed              []string `json:"targetsAnalyzed"`
}

type sourcePackage struct {
	listed listedPackage
	files  []*ast.File
	info   *types.Info
}

type analysisContext struct {
	generatedImport string
	derivedCommands map[*types.Named]bool
}

type packageImporter struct {
	checked  map[string]*types.Package
	fallback types.Importer
}

func (loader packageImporter) Import(path string) (*types.Package, error) {
	if found := loader.checked[path]; found != nil {
		return found, nil
	}
	return loader.fallback.Import(path)
}

func main() {
	root := flag.String("root", "", "repository root to inspect")
	goos := flag.String("goos", "", "target GOOS")
	goarch := flag.String("goarch", "", "target GOARCH")
	flag.Parse()
	if *root == "" || *goos == "" || *goarch == "" {
		fmt.Fprintln(os.Stderr, "analyze-cli: --root, --goos and --goarch are required")
		os.Exit(2)
	}

	result, err := analyze(*root, *goos, *goarch)
	if err != nil {
		fmt.Fprintf(os.Stderr, "analyze-cli: %v\n", err)
		os.Exit(1)
	}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		fmt.Fprintf(os.Stderr, "analyze-cli: encode result: %v\n", err)
		os.Exit(1)
	}
}

func analyze(root, goos, goarch string) (analysis, error) {
	packages, err := listPackages(root, goos, goarch)
	if err != nil {
		return analysis{}, fmt.Errorf("list %s/%s dependency closure: %w", goos, goarch, err)
	}
	result, err := analyzeTarget(packages)
	if err != nil {
		return analysis{}, fmt.Errorf("analyze %s/%s dependency closure: %w", goos, goarch, err)
	}
	modulePackages, err := listModulePackages(root, goos, goarch)
	if err != nil {
		return analysis{}, fmt.Errorf("list %s/%s module packages: %w", goos, goarch, err)
	}
	result.SQLiteAccess = hasSQLiteAccessOutsideStore(modulePackages)
	moduleTrust, moduleReleaseCoupling := stateExportFacts(modulePackages)
	result.StateExportTrust = result.StateExportTrust || moduleTrust
	result.StateExportReleaseCoupling = result.StateExportReleaseCoupling || moduleReleaseCoupling
	result.TargetsAnalyzed = []string{goos + "/" + goarch}
	return result, nil
}

func stateExportFacts(packages []listedPackage) (bool, bool) {
	modulePath := ""
	for _, candidate := range packages {
		if candidate.Module != nil && candidate.Module.Main && candidate.Module.Path != "" {
			modulePath = candidate.Module.Path
			break
		}
	}
	if modulePath == "" {
		return true, true
	}
	exportImport := modulePath + "/internal/stateexport"
	releaseImport := modulePath + "/internal/release"
	storeImport := modulePath + "/internal/store"
	trust := false
	coupling := false
	for _, candidate := range packages {
		for _, name := range append(append([]string(nil), candidate.GoFiles...), candidate.CgoFiles...) {
			file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(candidate.Dir, name), nil, parser.SkipObjectResolution)
			if err != nil {
				return true, true
			}
			aliases := make(map[string]string)
			sensitive := candidate.ImportPath == exportImport || (candidate.ImportPath == storeImport && strings.HasPrefix(name, "inventory_export"))
			for _, imported := range file.Imports {
				path, err := strconv.Unquote(imported.Path.Value)
				if err != nil {
					return true, true
				}
				alias := filepath.Base(path)
				if imported.Name != nil && imported.Name.Name != "_" && imported.Name.Name != "." {
					alias = imported.Name.Name
				}
				aliases[alias] = path
				if sensitive && path == "crypto/ed25519" {
					trust = true
				}
				if sensitive && path == releaseImport {
					coupling = true
				}
			}
			ast.Inspect(file, func(node ast.Node) bool {
				if sensitive {
					switch value := node.(type) {
					case *ast.Ident:
						normalized := strings.ToLower(strings.ReplaceAll(value.Name, "_", ""))
						if value.Name == "ReleaseTrustPolicy" {
							coupling = true
						}
						if normalized == "privatekey" || normalized == "signingseed" || normalized == "privatekeybytes" {
							trust = true
						}
					case *ast.BasicLit:
						if value.Kind == token.STRING {
							decoded, _ := strconv.Unquote(value.Value)
							if strings.Contains(decoded, "verified-against-supplied-policy") || strings.Contains(decoded, "release-trust-policy") {
								coupling = true
							}
						}
					}
				}
				literal, ok := node.(*ast.CompositeLit)
				if !ok {
					return true
				}
				selector, ok := unparenthesized(literal.Type).(*ast.SelectorExpr)
				if !ok {
					return true
				}
				prefix, prefixOK := selector.X.(*ast.Ident)
				if !prefixOK || selector.Sel.Name != "Config" || aliases[prefix.Name] != exportImport {
					return true
				}
				for _, element := range literal.Elts {
					pair, ok := element.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					key, keyOK := pair.Key.(*ast.Ident)
					if !keyOK || (key.Name != "Signer" && key.Name != "Verifier") {
						continue
					}
					identifier, isIdentifier := unparenthesized(pair.Value).(*ast.Ident)
					if !isIdentifier || identifier.Name != "nil" {
						trust = true
					}
				}
				return true
			})
		}
	}
	return trust, coupling
}

func listPackages(root, goos, goarch string) ([]listedPackage, error) {
	command := exec.Command("go", "list", "-deps", "-export", "-json", "./cmd/vsk-labs")
	command.Dir = root
	command.Env = targetEnvironment(goos, goarch)
	output, err := command.Output()
	if err != nil {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			return nil, fmt.Errorf("go list: %s", strings.TrimSpace(string(exitError.Stderr)))
		}
		return nil, fmt.Errorf("go list: %w", err)
	}

	decoder := json.NewDecoder(strings.NewReader(string(output)))
	var packages []listedPackage
	for {
		var candidate listedPackage
		if err := decoder.Decode(&candidate); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("decode go list output: %w", err)
		}
		packages = append(packages, candidate)
	}
	return packages, nil
}

func listModulePackages(root, goos, goarch string) ([]listedPackage, error) {
	command := exec.Command("go", "list", "-json", "./...")
	command.Dir = root
	command.Env = targetEnvironment(goos, goarch)
	output, err := command.Output()
	if err != nil {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			return nil, fmt.Errorf("go list: %s", strings.TrimSpace(string(exitError.Stderr)))
		}
		return nil, fmt.Errorf("go list: %w", err)
	}

	decoder := json.NewDecoder(strings.NewReader(string(output)))
	var packages []listedPackage
	for {
		var candidate listedPackage
		if err := decoder.Decode(&candidate); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("decode go list output: %w", err)
		}
		if candidate.Module != nil && candidate.Module.Main {
			packages = append(packages, candidate)
		}
	}
	return packages, nil
}

func hasSQLiteAccessOutsideStore(packages []listedPackage) bool {
	if len(packages) == 0 {
		return true
	}
	modulePath := ""
	for _, candidate := range packages {
		if candidate.Module != nil && candidate.Module.Main && candidate.Module.Path != "" {
			modulePath = candidate.Module.Path
			break
		}
	}
	if modulePath == "" {
		return true
	}
	storeImport := modulePath + "/internal/store"
	for _, candidate := range packages {
		if candidate.ImportPath == storeImport || strings.HasPrefix(candidate.ImportPath, storeImport+"/") {
			continue
		}
		for _, imported := range candidate.Imports {
			switch imported {
			case "database/sql", "github.com/ncruces/go-sqlite3", "github.com/ncruces/go-sqlite3/driver":
				if !reviewedLocalRecoverySQLiteSource(candidate, modulePath) {
					return true
				}
			}
		}
	}
	return false
}

func reviewedLocalRecoverySQLiteSource(candidate listedPackage, modulePath string) bool {
	if candidate.ImportPath != modulePath+"/internal/adapter/localbackup" || !containsString(candidate.GoFiles, "recovery_restore_linux.go") {
		return false
	}
	return digestSourceFiles(candidate.Dir, []string{"recovery_restore_linux.go"}) == "06b0a5a808e3470f65e87bb4288818c486b1dc628b2bab8c31180c927c4cf0c4" || digestSourceFiles(candidate.Dir, []string{"recovery_restore_linux.go"}) == "05fbbba51e5559fde882a58ca010f55c63eb6eb3f18604e27ad10c7ee2efffd6"
}

func targetEnvironment(goos, goarch string) []string {
	environment := make([]string, 0, len(os.Environ())+3)
	for _, entry := range os.Environ() {
		if strings.HasPrefix(entry, "CGO_ENABLED=") || strings.HasPrefix(entry, "GOOS=") || strings.HasPrefix(entry, "GOARCH=") {
			continue
		}
		environment = append(environment, entry)
	}
	return append(environment, "CGO_ENABLED=0", "GOOS="+goos, "GOARCH="+goarch)
}

func analyzeTarget(listed []listedPackage) (analysis, error) {
	if len(listed) == 0 {
		return analysis{}, errors.New("dependency closure contains no in-module packages")
	}
	modulePath := ""
	var inModule []listedPackage
	for _, candidate := range listed {
		if candidate.Module != nil && candidate.Module.Main {
			inModule = append(inModule, candidate)
			if candidate.Module.Path != "" {
				modulePath = candidate.Module.Path
			}
		}
	}
	if modulePath == "" || len(inModule) == 0 {
		return analysis{}, errors.New("main module path is unavailable")
	}
	mainImport := modulePath + "/cmd/vsk-labs"
	generatedImport := modulePath + "/internal/generated"
	releaseImport := modulePath + "/internal/release"
	stateExportImport := modulePath + "/internal/stateexport"
	auditImport := modulePath + "/internal/audit"
	recoveryImport := modulePath + "/internal/recovery"
	identityImport := modulePath + "/internal/identity"
	apiImport := modulePath + "/internal/api"
	serverImport := modulePath + "/internal/server"
	localAPIImport := modulePath + "/internal/localapi"
	localTransportImport := modulePath + "/internal/localtransport"
	sshTransportImport := modulePath + "/internal/sshtransport"
	nativeCredentialImport := modulePath + "/internal/adapter/nativecredential"
	localRetentionImport := modulePath + "/internal/adapter/localretention"
	backupImport := modulePath + "/internal/backup"
	cliImport := modulePath + "/internal/cli"
	clientFileImport := modulePath + "/internal/clientfile"
	serverConfigImport := modulePath + "/internal/serverconfig"
	qualificationImport := modulePath + "/internal/qualification"
	if !containsPackage(inModule, mainImport) || !containsPackage(inModule, generatedImport) {
		return analysis{}, errors.New("runtime dependency closure omits the executable or generated package")
	}

	checked := make(map[string]*types.Package)
	targetLoader, err := exportDataImporter(listed)
	if err != nil {
		return analysis{}, err
	}
	loader := packageImporter{checked: checked, fallback: targetLoader}
	var result analysis
	standardPackages := make(map[string]bool)
	for _, candidate := range listed {
		if candidate.Standard {
			standardPackages[candidate.ImportPath] = true
		}
	}
	standardNetworkPackages := standardNetworkClosure(listed)
	result.LocalClientBoundary = true
	restoreCLISeen, restoreCLIValid := false, false
	restoreClientSeen, restoreClientValid := false, false
	localClosure := moduleDependencyClosure(inModule, localAPIImport)
	// The finite recovery witness command uses one byte-sealed package surface.
	// Do not turn the server-only recovery engine behind that package into a
	// portable CLI capability merely because Go compiles packages as a unit.
	controlClosure := moduleDependencyClosurePruned(inModule, cliImport, map[string]bool{recoveryImport: true})
	for importPath := range moduleDependencyClosure(inModule, clientFileImport) {
		controlClosure[importPath] = true
	}
	controlClosure[mainImport] = true
	// The root-only finite native API child is a private executable mode.
	// Prune only its main edge after both complete source closures are sealed;
	// a portable CLI import or any drift still receives the ordinary checks.
	sealedNativeMode := false
	sealedMainMode := false
	for _, candidate := range inModule {
		current := checkedSourcePackage{listed: candidate}
		sealedNativeMode = sealedNativeMode || reviewedPhase228Package(current, modulePath, "internal/qualification")
		sealedMainMode = sealedMainMode || reviewedPhase228Package(current, modulePath, "cmd/vsk-labs")
	}
	for _, candidate := range inModule {
		if candidate.ImportPath != mainImport {
			continue
		}
		for _, imported := range candidate.Imports {
			if imported == qualificationImport && sealedNativeMode && sealedMainMode {
				continue
			}
			// The server and the exact reviewed backup-custody package are private
			// executable modes, not portable CLI control capabilities. Both remain
			// subject to their dedicated whole-package and subprocess guards.
			if imported == cliImport || imported == serverImport || strings.HasPrefix(imported, serverImport+"/") || imported == backupImport {
				continue
			}
			for importPath := range moduleDependencyClosure(inModule, imported) {
				controlClosure[importPath] = true
			}
		}
	}
	if len(localClosure) > 0 && !reviewedLocalClientDependencies(localClosure, modulePath, localAPIImport, localTransportImport, sshTransportImport) {
		result.LocalClientBoundary = false
	}
	for _, candidate := range inModule {
		parsed, err := parseAndCheck(candidate, loader)
		if err != nil {
			return analysis{}, err
		}
		checked[candidate.ImportPath] = parsed.infoPackage()
		if candidate.ImportPath == cliImport && containsString(candidate.GoFiles, "restore.go") {
			restoreCLISeen, restoreCLIValid = true, reviewedRestoreCLIFile(candidate.Dir)
		}
		if candidate.ImportPath == localAPIImport && containsString(candidate.GoFiles, "restore_client.go") {
			restoreClientSeen, restoreClientValid = true, reviewedRestoreClientFile(candidate.Dir)
		}
		if candidate.ImportPath == localRetentionImport && !reviewedLocalRetentionPackage(parsed, localRetentionImport) {
			result.ControlProviderAccess = true
		}
		if candidate.ImportPath == mainImport && !reviewedMainComposition(parsed, modulePath, cliImport, clientFileImport, releaseImport, serverImport) {
			result.ControlProviderAccess = true
		}
		// The persistent server's generated forced-command handler forwards one
		// allowlisted frame back to its own protected socket. Other consumers
		// remain forbidden; server code is outside the portable client closure.
		if candidate.ImportPath != serverImport && candidate.ImportPath != localAPIImport && candidate.ImportPath != localTransportImport && candidate.ImportPath != sshTransportImport && containsString(candidate.Imports, localTransportImport) {
			result.LocalClientBoundary = false
		}
		if localClosure[candidate.ImportPath] && !reviewedLocalClientPackage(parsed, modulePath, localAPIImport, localTransportImport, sshTransportImport) {
			result.LocalClientBoundary = false
		}
		isReleasePackage := candidate.ImportPath == releaseImport || strings.HasPrefix(candidate.ImportPath, releaseImport+"/")
		isControlPackage := controlClosure[candidate.ImportPath]
		// The native credential package is a byte-for-byte sealed Linux OS adapter.
		// Its D-Bus and /proc surface is reviewed as a whole, never as a portable
		// control client capability. Any source or import change breaks this seal.
		sealedNativeCredential := reviewedNativeCredentialPackage(parsed, nativeCredentialImport, modulePath)
		sealedHostAction := reviewedHostActionPackage(parsed, modulePath, "internal/hostaction")
		sealedHostAction = sealedHostAction || reviewedPhase228Package(parsed, modulePath, "internal/hostaction")
		sealedHostActionMain := reviewedHostActionPackage(parsed, modulePath, "cmd/vsk-labs")
		sealedHostActionMain = sealedHostActionMain || reviewedPhase228Package(parsed, modulePath, "cmd/vsk-labs")
		sealedDebianAccess := reviewedLinuxRolePackage(parsed, modulePath, "internal/linuxrole") || reviewedDebianAccessPackage(parsed, modulePath, "internal/debianaccess") || reviewedDebianBaselinePackage(parsed, modulePath, "internal/debianaccess") || reviewedDebianBaselinePackage(parsed, modulePath, "internal/debianbaseline")
		sealedDebianAccess = sealedDebianAccess || reviewedPhase228Package(parsed, modulePath, "internal/linuxrole") || reviewedPhase228Package(parsed, modulePath, "internal/debianaccess") || reviewedPhase228Package(parsed, modulePath, "internal/debianbaseline")
		sealedAccessAdapter := reviewedLinuxRolePackage(parsed, modulePath, "internal/adapter/hostaction") || reviewedDebianAccessPackage(parsed, modulePath, "internal/adapter/hostaction") || reviewedDebianBaselinePackage(parsed, modulePath, "internal/adapter/hostaction")
		sealedAccessAdapter = sealedAccessAdapter || reviewedPhase228Package(parsed, modulePath, "internal/adapter/hostaction")
		sealedQualification := reviewedPhase228Package(parsed, modulePath, "internal/qualification")
		sealedRecoveryCustodian := candidate.ImportPath == recoveryImport && reviewedRecoveryCustodianPackage(parsed)
		isControlCapabilityPackage := isControlPackage && !(localClosure[candidate.ImportPath] && !result.LocalClientBoundary) && !sealedNativeCredential && !sealedRecoveryCustodian && !sealedHostAction && !sealedDebianAccess
		// The custodian command imports recovery's fixed protected pin/receipt
		// source. Only this exact reviewed source closure may carry those paths.
		inspectControlPaths := isControlPackage && candidate.ImportPath != generatedImport && candidate.ImportPath != serverConfigImport && !sealedNativeCredential && !sealedRecoveryCustodian && !sealedHostAction && !sealedHostActionMain && !sealedDebianAccess
		for _, imported := range candidate.Imports {
			if imported == "os/exec" && !isReleasePackage && !(candidate.ImportPath == sshTransportImport && reviewedSSHTransportPackage(parsed, localTransportImport)) && !reviewedNativeCredentialPackage(parsed, nativeCredentialImport, modulePath) && !reviewedBackupProcessPackage(parsed, backupImport) && !reviewedPhase228ReceiveProcess(parsed, serverImport) && !sealedDebianAccess && !sealedAccessAdapter && !sealedQualification {
				result.ShellDispatch = true
			}
			switch imported {
			case "crypto/ecdsa":
				result.StateExportTrust = true
			case "crypto/ed25519":
				// Issue #107 verifies independently signed audit checkpoints
				// with public material only. Seal that exact package; every
				// other Ed25519 dependency remains forbidden production trust.
				if !(candidate.ImportPath == auditImport && reviewedAuditVerificationPackage(parsed)) &&
					!(candidate.ImportPath == recoveryImport && (reviewedRecoveryVerificationPackage(parsed) || reviewedRecoveryCustodianPackage(parsed))) &&
					!reviewedRecoveryDenialVerificationPackage(parsed, modulePath) &&
					!reviewedRecoveryCanaryVerificationFile(parsed, serverImport) && !sealedHostAction && !sealedDebianAccess && !reviewedHostActionServerSigner(parsed, serverImport) {
					result.StateExportTrust = true
				}
			case "crypto/rsa":
				// The remote-identity adapter verifies RSA public keys. Keep the
				// executable-wide signing guard everywhere else; state-export
				// composition is independently checked below.
				if candidate.ImportPath != identityImport {
					result.StateExportTrust = true
				}
			}
			if isReleasePackage {
				if standardNetworkPackages[imported] || imported == "github.com/sigstore/sigstore-go/pkg/tuf" {
					result.ReleaseNetworkAccess = true
				}
				switch imported {
				case "os/exec", "plugin":
					result.ReleaseArtifactExecution = true
				}
			}
			if isControlCapabilityPackage {
				switch imported {
				case "database/sql", "github.com/ncruces/go-sqlite3", "github.com/ncruces/go-sqlite3/driver":
					result.ControlSQLiteAccess = true
				case "os/exec", "plugin":
					if !(candidate.ImportPath == sshTransportImport && reviewedSSHTransportPackage(parsed, localTransportImport)) && !reviewedNativeCredentialPackage(parsed, nativeCredentialImport, modulePath) {
						result.ControlShellDispatch = true
					}
				case "crypto/tls", "syscall":
					if !reviewedControlNetworkImport(parsed, imported, mainImport, localAPIImport, localTransportImport, sshTransportImport, serverConfigImport) {
						result.ControlArbitraryHTTP = true
					}
				}
				if standardNetworkPackages[imported] && !reviewedControlNetworkImport(parsed, imported, mainImport, localAPIImport, localTransportImport, sshTransportImport, serverConfigImport) {
					result.ControlArbitraryHTTP = true
				}
				if !reviewedControlExternalImport(parsed, imported, standardPackages[imported], modulePath, localAPIImport, clientFileImport, serverConfigImport, releaseImport) {
					result.ControlProviderAccess = true
				}
				if strings.Contains(imported, "google.golang.org") || strings.Contains(imported, "/google") || strings.Contains(imported, "sheets") {
					result.ControlGoogleAccess = true
				}
				if strings.HasPrefix(imported, modulePath+"/internal/inventory") || strings.HasPrefix(imported, modulePath+"/internal/profiles/") || imported == modulePath+"/internal/store" || imported == modulePath+"/internal/stateexport" {
					result.InventoryDirectDomain = true
				}
				if strings.Contains(imported, "/cloudflare") || strings.Contains(imported, "/coolify") || strings.Contains(imported, "/harbor") || strings.Contains(imported, "/onepassword") {
					result.ControlProviderAccess = true
				}
			}
		}
		if !sealedNativeCredential {
			registryGeneratedOrReviewed := sealedHostAction || sealedHostActionMain || sealedDebianAccess || sealedAccessAdapter || sealedQualification || candidate.ImportPath == apiImport || candidate.ImportPath == localAPIImport || (candidate.ImportPath == recoveryImport && reviewedRecoveryCustodianPackage(parsed)) ||
				(candidate.ImportPath == modulePath+"/internal/adapter/hostdiscovery" && reviewedHostDiscoveryCollectorPackage(parsed))
			inspectPackage(parsed, generatedImport, stateExportImport, isReleasePackage, registryGeneratedOrReviewed, inspectControlPaths, &result)
		}
	}
	result.RestoreCommandClosureInvalid = restoreCLISeen != restoreClientSeen || restoreCLISeen && (!restoreCLIValid || !restoreClientValid)
	return result, nil
}

func reviewedRestoreCLIFile(directory string) bool {
	return reviewedRestoreSource(filepath.Join(directory, "restore.go"), []string{
		"generated.ValidateContractJSON", "generated.SchemaIDRestoreRequest", "generated.SchemaIDRestoreRunRequest", "generated.SchemaIDRestoreVerifyRequest",
		"control.PlanRestore", "control.RunRestore", "control.VerifyRestore",
	}, []string{"os/exec", "database/sql", "productionDatabasePath", "RestoreSnapshot", "os.Rename"})
}

func reviewedRestoreClientFile(directory string) bool {
	return reviewedRestoreSource(filepath.Join(directory, "restore_client.go"), []string{
		`"/api/v1/recovery-points/"`, `"/restore-plans"`, `"/api/v1/restore-plans/"`, `"/runs"`, `"/verifications"`,
		`"api.v1.restores.plan"`, `"api.v1.restores.run"`, `"api.v1.restores.verify"`,
		"generated.ValidateContractJSON", "data.PriorRecoveryEpoch == result.RecoveryEpoch", "data.NextRecoveryEpoch == result.RecoveryEpoch",
	}, []string{"os/exec", "database/sql", "productionDatabasePath", "RestoreSnapshot", "os.Rename", "net/http"})
}

func reviewedRestoreSource(path string, required, forbidden []string) bool {
	source, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	text := string(source)
	for _, marker := range required {
		if !strings.Contains(text, marker) {
			return false
		}
	}
	for _, marker := range forbidden {
		if strings.Contains(text, marker) {
			return false
		}
	}
	return true
}

// #228 adds only these reviewed complete source/import closures. Historical
// wave seals stay unchanged; another file, import or byte change fails closed.
var phase228SourceSeals = map[string]hostActionSourceSeal{
	"cmd/vsk-labs|access_rollback_linux.go,host_action_linux.go,main.go,native_probe_linux.go": {imports: []string{"context", "crypto/rand", "encoding/hex", "github.com/vegastack/vegastack-labs/internal/adapter/nativecredential", "github.com/vegastack/vegastack-labs/internal/backup", "github.com/vegastack/vegastack-labs/internal/cli", "github.com/vegastack/vegastack-labs/internal/clientfile", "github.com/vegastack/vegastack-labs/internal/debianaccess", "github.com/vegastack/vegastack-labs/internal/debianbaseline", "github.com/vegastack/vegastack-labs/internal/hostaction", "github.com/vegastack/vegastack-labs/internal/linuxrole", "github.com/vegastack/vegastack-labs/internal/qualification", "github.com/vegastack/vegastack-labs/internal/release", "github.com/vegastack/vegastack-labs/internal/result", "github.com/vegastack/vegastack-labs/internal/server", "os", "os/signal", "strconv", "syscall", "time"}, digest: "ef3009e4418226485a2beab3c65b166855cc1dc648ab05a88080fca1e3231cf7"},
	"internal/qualification|api_child_linux.go,baseline_stage_evidence.go,cleanup_linux.go,client_profile.go,client_profile_linux.go,confinement_linux.go,control_handoff_evidence.go,control_setup_bootstrap_linux.go,control_setup_evidence.go,control_setup_observation_linux.go,control_setup_profile.go,control_setup_profile_linux.go,control_setup_service_linux.go,control_setup_supervisor_linux.go,controller_identity_linux.go,controller_selection.go,credential_stage_evidence.go,disk_linux.go,fail2ban.go,fail2ban_linux.go,fixture_approval.go,fixture_approval_linux.go,guest_identity_linux.go,native_credential_evidence.go,native_linux.go,observer.go,observer_linux.go,observer_outer_linux.go,owned_files_linux.go,owned_guest_linux.go,physical_host_linux.go,preparation_linux.go,protocol_stage_evidence.go,qmp_linux.go,reboot_linux.go,recovery_evidence.go,recovery_negative.go,recovery_negative_evidence.go,replacement_memory_linux.go,report.go,report_progress.go,role_stage_evidence.go,rollback_witness.go,scenario_witness.go,scope.go,scope_linux.go,serial_linux.go,slack_fixture_peer.go,slack_fixture_peer_linux.go,slot_transfer_linux.go,stage_evidence.go,stage_report.go,step_linux.go,step_validation.go,suitability.go,transport_probe_linux.go,volume_stage_evidence.go,witness_linux.go,witness_memory_linux.go": {imports: []string{"bufio", "bytes", "context", "crypto/rand", "crypto/sha256", "crypto/subtle", "crypto/tls", "crypto/x509", "encoding/base64", "encoding/hex", "encoding/json", "errors", "fmt", "github.com/coder/websocket", "github.com/vegastack/vegastack-labs/internal/adapter/hostdiscovery", "github.com/vegastack/vegastack-labs/internal/adapter/nativecredential", "github.com/vegastack/vegastack-labs/internal/credentialref", "github.com/vegastack/vegastack-labs/internal/debianaccess", "github.com/vegastack/vegastack-labs/internal/debianbaseline", "github.com/vegastack/vegastack-labs/internal/generated", "github.com/vegastack/vegastack-labs/internal/hostaction", "github.com/vegastack/vegastack-labs/internal/hostadoption", "github.com/vegastack/vegastack-labs/internal/hostdiscovery", "github.com/vegastack/vegastack-labs/internal/hostreplacement", "github.com/vegastack/vegastack-labs/internal/linuxrole", "github.com/vegastack/vegastack-labs/internal/localapi", "github.com/vegastack/vegastack-labs/internal/result", "github.com/vegastack/vegastack-labs/internal/serverconfig", "github.com/vegastack/vegastack-labs/internal/strictjson", "golang.org/x/crypto/ssh", "golang.org/x/sys/unix", "io", "net", "net/http", "net/netip", "os", "os/exec", "os/user", "path/filepath", "reflect", "regexp", "slices", "sort", "strconv", "strings", "sync", "syscall", "time"}, digest: "f0f3a6e4eb725bf172ce683baba3c33c0d843a9ae7c0737a391182c32980ce6f"},
	"internal/debianaccess|baseline.go,baseline_profiles_unix.go,baseline_unix.go,configuration.go,destinations_unix.go,draft.go,fail2ban.go,handler.go,input.go,native_observation.go,native_observation_linux.go,observations_unix.go,preparation.go,probe.go,probe_socket.go,probe_udp.go,rollback.go,rollback_unix.go,runner.go,runtime_unix.go,sequence.go,sequence_policy.go,sessions_linux.go,source_probe.go,source_probe_linux.go,sudo_policy.go,sudo_policy_unix.go,timer.go,timer_unix.go":                                                                                                                                                                                                                                                                                                                       {imports: []string{"bytes", "context", "crypto/ed25519", "crypto/rand", "crypto/sha256", "encoding/hex", "encoding/json", "errors", "fmt", "github.com/godbus/dbus/v5", "github.com/vegastack/vegastack-labs/internal/credentialref", "github.com/vegastack/vegastack-labs/internal/generated", "github.com/vegastack/vegastack-labs/internal/hostaction", "github.com/vegastack/vegastack-labs/internal/strictjson", "golang.org/x/crypto/ssh", "golang.org/x/sys/unix", "io", "net", "net/netip", "os", "os/exec", "path", "path/filepath", "regexp", "runtime", "sort", "strconv", "strings", "sync/atomic", "syscall", "time"}, digest: "151f58459dcfc945d5c9b7119639d4ea427e63387e0f9d1386b94faca6304dda"},
	"internal/debianbaseline|aide.go,apparmor.go,apply_unix.go,apt_unix.go,audit.go,collect.go,fail2ban.go,handler.go,health.go,input.go,native_unix.go,policy.go,reader.go,time_unix.go,volume_files_unix.go,volume_linux.go,volume_mapping.go,volume_metadata.go,volume_native_cases_linux.go,volume_native_witness_linux.go,volume_recovery_linux.go,volume_recovery_unix.go":                                                                                                                                                                                                                                                                                                                                                                                                                                            {imports: []string{"bytes", "context", "crypto/sha256", "encoding/binary", "encoding/hex", "encoding/json", "errors", "fmt", "github.com/vegastack/vegastack-labs/internal/debianaccess", "github.com/vegastack/vegastack-labs/internal/generated", "github.com/vegastack/vegastack-labs/internal/hostaction", "github.com/vegastack/vegastack-labs/internal/strictjson", "golang.org/x/sys/unix", "io", "math", "net/netip", "os", "os/exec", "path", "path/filepath", "reflect", "regexp", "runtime", "slices", "sort", "strconv", "strings", "syscall", "time"}, digest: "add040d65a4dabd41c30b5fda0ebb4c82aefbed0208395affe8c7c0c306b7a23"},
	"internal/linuxrole|boot_linux.go,collect_linux.go,control_handoff_linux.go,control_install.go,handler.go,input.go,isolation_linux.go,native_control_observation.go,native_control_observation_linux.go,native_recovery_destination_linux.go,native_recovery_recheck_linux.go,prepare.go,runtime_linux.go":                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              {imports: []string{"bytes", "context", "crypto/sha256", "encoding/hex", "encoding/json", "errors", "fmt", "github.com/vegastack/vegastack-labs/internal/debianaccess", "github.com/vegastack/vegastack-labs/internal/debianbaseline", "github.com/vegastack/vegastack-labs/internal/generated", "github.com/vegastack/vegastack-labs/internal/hostaction", "github.com/vegastack/vegastack-labs/internal/strictjson", "golang.org/x/sys/unix", "io", "net", "net/http", "os", "os/exec", "path", "reflect", "regexp", "runtime", "slices", "sort", "strconv", "strings", "syscall", "time"}, digest: "0bc27fb83e44084428f978aae6d8385c4210cc49d1eb4eb22c3e8570aa67eb7c"},
	"internal/adapter/hostaction|access_render.go,access_render_lock.go,access_render_unix.go,access_sequence.go,adapter.go,baseline_render.go,linux_role_render.go,native_probe.go,profile_renderer.go,recovery_payload.go,ssh.go":                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         {imports: []string{"bufio", "bytes", "context", "encoding/base64", "encoding/json", "github.com/vegastack/vegastack-labs/ansible", "github.com/vegastack/vegastack-labs/internal/adapter", "github.com/vegastack/vegastack-labs/internal/credentialref", "github.com/vegastack/vegastack-labs/internal/debianaccess", "github.com/vegastack/vegastack-labs/internal/debianbaseline", "github.com/vegastack/vegastack-labs/internal/failure", "github.com/vegastack/vegastack-labs/internal/generated", "github.com/vegastack/vegastack-labs/internal/hostaction", "github.com/vegastack/vegastack-labs/internal/linuxrole", "github.com/vegastack/vegastack-labs/internal/strictjson", "golang.org/x/crypto/ssh", "io", "io/fs", "net", "os", "os/exec", "path/filepath", "strconv", "strings", "sync", "syscall", "time"}, digest: "a9d9e83e3f42638328036eae287238dbc7ebf2739a964b0cc2a83a004ef9a438"},
	"internal/localapi|apply_bound.go,approval_client.go,audit_client.go,authorization_grants.go,backup_client.go,client.go,credential_client.go,credential_lifecycle_client.go,database_client.go,gates_client.go,hosts_client.go,listener.go,listener_linux.go,qualification_client.go,qualification_producer.go,restore_client.go,schedule_client.go":                                                                                                                                                                                                                                                                                                                                                                                                                                                                    {imports: []string{"bytes", "context", "crypto/sha256", "encoding/hex", "encoding/json", "errors", "github.com/vegastack/vegastack-labs/internal/credentialref", "github.com/vegastack/vegastack-labs/internal/failure", "github.com/vegastack/vegastack-labs/internal/generated", "github.com/vegastack/vegastack-labs/internal/hostaction", "github.com/vegastack/vegastack-labs/internal/localtransport", "github.com/vegastack/vegastack-labs/internal/principal", "github.com/vegastack/vegastack-labs/internal/result", "github.com/vegastack/vegastack-labs/internal/runprotocol", "github.com/vegastack/vegastack-labs/internal/serverconfig", "github.com/vegastack/vegastack-labs/internal/sshtransport", "golang.org/x/sys/unix", "io", "mime", "net", "os", "path/filepath", "runtime", "strconv", "strings", "sync", "time"}, digest: "e44917786a29e5f2a1d6f4a95fefa7d1951ee28fbf7ffaf7800b1ba246402904"},
	"internal/recovery|artifact.go,audit_continuity.go,bound_canary_noop.go,canary.go,canary_capabilities.go,canary_ports.go,candidate.go,candidate_authority.go,candidate_destination.go,candidate_destination_linux.go,candidate_linux.go,candidate_transfer.go,candidate_transfer_linux.go,candidate_transfer_source_linux.go,collector.go,custody.go,fence.go,fence_admission.go,fence_coordinator.go,fence_evidence.go,fence_execution.go,fence_witness.go,host_generation_fence.go,host_replacement_continuity.go,manifest.go,manifest_file_unix.go,offsite_source.go,operations.go,package_file_unix.go,qualification.go,qualified_registry_linux.go,receipt_file_unix.go,source.go,source_admission.go,source_admission_file_unix.go,source_handoff.go,store_canary.go,store_operations.go,transport.go,witness.go": {imports: []string{"bytes", "context", "crypto/aes", "crypto/cipher", "crypto/ecdh", "crypto/ed25519", "crypto/hkdf", "crypto/rand", "crypto/sha256", "crypto/subtle", "encoding/hex", "encoding/json", "errors", "github.com/vegastack/vegastack-labs/internal/adapter", "github.com/vegastack/vegastack-labs/internal/adapter/recoverydenial", "github.com/vegastack/vegastack-labs/internal/audit", "github.com/vegastack/vegastack-labs/internal/authorization", "github.com/vegastack/vegastack-labs/internal/backup", "github.com/vegastack/vegastack-labs/internal/change", "github.com/vegastack/vegastack-labs/internal/failure", "github.com/vegastack/vegastack-labs/internal/generated", "github.com/vegastack/vegastack-labs/internal/hostaction", "github.com/vegastack/vegastack-labs/internal/hostreplacement", "github.com/vegastack/vegastack-labs/internal/identity", "github.com/vegastack/vegastack-labs/internal/linuxrole", "github.com/vegastack/vegastack-labs/internal/plan", "github.com/vegastack/vegastack-labs/internal/run", "github.com/vegastack/vegastack-labs/internal/store", "golang.org/x/sys/unix", "io", "io/fs", "math", "os", "path/filepath", "regexp", "sort", "strconv", "sync/atomic", "syscall", "time"}, digest: "5063481e92f75d383ddb3d15a3261cb43b8f9313a6cad97f0b64eac2f7de9205"},
	"internal/debianaccess|baseline.go,baseline_profiles_unix.go,baseline_unix.go,configuration.go,destinations_unix.go,draft.go,fail2ban.go,handler.go,input.go,native_observation.go,native_observation_unsupported.go,observations_unix.go,preparation.go,probe.go,probe_socket.go,probe_udp.go,rollback.go,rollback_unix.go,runner.go,runtime_unix.go,sequence.go,sequence_policy.go,sessions_unsupported.go,source_probe.go,source_probe_unsupported.go,sudo_policy.go,sudo_policy_unix.go,timer.go,timer_unix.go":                                                                                                                                                                                                                                                                                                     {imports: []string{"bytes", "context", "crypto/ed25519", "crypto/rand", "crypto/sha256", "encoding/hex", "encoding/json", "errors", "fmt", "github.com/vegastack/vegastack-labs/internal/credentialref", "github.com/vegastack/vegastack-labs/internal/generated", "github.com/vegastack/vegastack-labs/internal/hostaction", "github.com/vegastack/vegastack-labs/internal/strictjson", "golang.org/x/crypto/ssh", "golang.org/x/sys/unix", "io", "net", "net/netip", "os", "os/exec", "path", "regexp", "runtime", "sort", "strconv", "strings", "sync/atomic", "syscall", "time"}, digest: "6510c2f2a659bf5d14e05b3de873675568030b05c50d401107604bce1d2f292b"},
	"internal/linuxrole|control_install.go,handler.go,input.go,native_control_observation.go,native_control_observation_unsupported.go,native_recovery_destination_unsupported.go,prepare.go,runtime_unsupported.go":                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        {imports: []string{"context", "crypto/sha256", "encoding/hex", "encoding/json", "errors", "fmt", "github.com/vegastack/vegastack-labs/internal/debianaccess", "github.com/vegastack/vegastack-labs/internal/generated", "github.com/vegastack/vegastack-labs/internal/hostaction", "github.com/vegastack/vegastack-labs/internal/strictjson", "reflect", "regexp", "slices", "strings", "time"}, digest: "23087beaf21cb1bf7c659a62d29b4801ce793675bf5700ad75f24d3dc68c3c85"},
	"internal/localapi|apply_bound.go,approval_client.go,audit_client.go,authorization_grants.go,backup_client.go,client.go,credential_client.go,credential_lifecycle_client.go,database_client.go,gates_client.go,hosts_client.go,listener.go,listener_unsupported.go,qualification_client.go,qualification_producer.go,restore_client.go,schedule_client.go":                                                                                                                                                                                                                                                                                                                                                                                                                                                              {imports: []string{"bytes", "context", "crypto/sha256", "encoding/hex", "encoding/json", "errors", "github.com/vegastack/vegastack-labs/internal/credentialref", "github.com/vegastack/vegastack-labs/internal/failure", "github.com/vegastack/vegastack-labs/internal/generated", "github.com/vegastack/vegastack-labs/internal/hostaction", "github.com/vegastack/vegastack-labs/internal/localtransport", "github.com/vegastack/vegastack-labs/internal/principal", "github.com/vegastack/vegastack-labs/internal/result", "github.com/vegastack/vegastack-labs/internal/runprotocol", "github.com/vegastack/vegastack-labs/internal/serverconfig", "github.com/vegastack/vegastack-labs/internal/sshtransport", "io", "mime", "net", "runtime", "strconv", "strings", "sync", "time"}, digest: "38742d70642dbf778c3d66ce65cd9cf7942edfef15e5f8bfc4c107b229a71f55"},
	"internal/recovery|artifact.go,audit_continuity.go,bound_canary_noop.go,canary.go,canary_capabilities.go,canary_ports.go,candidate.go,candidate_authority.go,candidate_destination.go,candidate_transfer.go,candidate_transfer_unsupported.go,candidate_unsupported.go,collector.go,custody.go,fence.go,fence_admission.go,fence_coordinator.go,fence_evidence.go,fence_execution.go,fence_witness.go,host_generation_fence.go,host_replacement_continuity.go,manifest.go,manifest_file_unix.go,offsite_source.go,operations.go,package_file_unix.go,qualification.go,qualified_registry_unsupported.go,receipt_file_unix.go,source.go,source_admission.go,source_admission_file_unix.go,source_handoff.go,store_canary.go,store_operations.go,transport.go,witness.go":                                                 {imports: []string{"bytes", "context", "crypto/aes", "crypto/cipher", "crypto/ecdh", "crypto/ed25519", "crypto/hkdf", "crypto/rand", "crypto/sha256", "crypto/subtle", "encoding/hex", "encoding/json", "errors", "github.com/vegastack/vegastack-labs/internal/adapter", "github.com/vegastack/vegastack-labs/internal/adapter/recoverydenial", "github.com/vegastack/vegastack-labs/internal/audit", "github.com/vegastack/vegastack-labs/internal/authorization", "github.com/vegastack/vegastack-labs/internal/backup", "github.com/vegastack/vegastack-labs/internal/change", "github.com/vegastack/vegastack-labs/internal/failure", "github.com/vegastack/vegastack-labs/internal/generated", "github.com/vegastack/vegastack-labs/internal/hostaction", "github.com/vegastack/vegastack-labs/internal/hostreplacement", "github.com/vegastack/vegastack-labs/internal/identity", "github.com/vegastack/vegastack-labs/internal/linuxrole", "github.com/vegastack/vegastack-labs/internal/plan", "github.com/vegastack/vegastack-labs/internal/run", "github.com/vegastack/vegastack-labs/internal/store", "golang.org/x/sys/unix", "io", "os", "path/filepath", "regexp", "sort", "strconv", "sync/atomic", "time"}, digest: "5ffff4796a1572434e1ffb0a785e3acbe4e03f9992f0b9d1f7c6aee081bf728a"},
	"internal/debianaccess|baseline.go,configuration.go,draft.go,fail2ban.go,handler.go,input.go,native_observation.go,native_observation_unsupported.go,preparation.go,probe.go,probe_socket.go,probe_udp.go,rollback.go,runner.go,sequence.go,sequence_policy.go,sessions_unsupported.go,source_probe.go,source_probe_unsupported.go,sudo_policy.go,timer.go":                                                                                                                                                                                                                                                                                                                                                                                                                                                             {imports: []string{"bytes", "context", "crypto/ed25519", "crypto/rand", "crypto/sha256", "encoding/hex", "encoding/json", "errors", "fmt", "github.com/vegastack/vegastack-labs/internal/credentialref", "github.com/vegastack/vegastack-labs/internal/generated", "github.com/vegastack/vegastack-labs/internal/hostaction", "github.com/vegastack/vegastack-labs/internal/strictjson", "golang.org/x/crypto/ssh", "io", "net", "net/netip", "os", "os/exec", "path", "regexp", "sort", "strconv", "strings", "sync/atomic", "syscall", "time"}, digest: "5fa4cf206888730d423bf290519b4eeebe7ae88184f945e4c92d93653b820254"},
	"internal/adapter/hostaction|access_render.go,access_render_lock.go,access_render_unsupported.go,access_sequence.go,adapter.go,baseline_render.go,linux_role_render.go,native_probe.go,profile_renderer.go,recovery_payload.go,ssh.go":                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  {imports: []string{"bufio", "bytes", "context", "encoding/base64", "encoding/json", "github.com/vegastack/vegastack-labs/ansible", "github.com/vegastack/vegastack-labs/internal/adapter", "github.com/vegastack/vegastack-labs/internal/credentialref", "github.com/vegastack/vegastack-labs/internal/debianaccess", "github.com/vegastack/vegastack-labs/internal/debianbaseline", "github.com/vegastack/vegastack-labs/internal/failure", "github.com/vegastack/vegastack-labs/internal/generated", "github.com/vegastack/vegastack-labs/internal/hostaction", "github.com/vegastack/vegastack-labs/internal/linuxrole", "github.com/vegastack/vegastack-labs/internal/strictjson", "golang.org/x/crypto/ssh", "io", "io/fs", "net", "os", "os/exec", "path/filepath", "strconv", "strings", "sync", "time"}, digest: "45a15b492c48e8dcc487d169dea1deb7aab7b80ed8a37be049964421ca5234e0"},
	"internal/recovery|artifact.go,audit_continuity.go,bound_canary_noop.go,canary.go,canary_capabilities.go,canary_ports.go,candidate.go,candidate_authority.go,candidate_destination.go,candidate_transfer.go,candidate_transfer_unsupported.go,candidate_unsupported.go,collector.go,custody.go,fence.go,fence_admission.go,fence_coordinator.go,fence_evidence.go,fence_execution.go,fence_witness.go,host_generation_fence.go,host_replacement_continuity.go,manifest.go,manifest_file_unsupported.go,offsite_source.go,operations.go,package_file_unsupported.go,qualification.go,qualified_registry_unsupported.go,receipt_file_unsupported.go,source.go,source_admission.go,source_admission_file_unsupported.go,source_handoff.go,store_canary.go,store_operations.go,transport.go,witness.go":                     {imports: []string{"bytes", "context", "crypto/aes", "crypto/cipher", "crypto/ecdh", "crypto/ed25519", "crypto/hkdf", "crypto/rand", "crypto/sha256", "crypto/subtle", "encoding/hex", "encoding/json", "errors", "github.com/vegastack/vegastack-labs/internal/adapter", "github.com/vegastack/vegastack-labs/internal/adapter/recoverydenial", "github.com/vegastack/vegastack-labs/internal/audit", "github.com/vegastack/vegastack-labs/internal/authorization", "github.com/vegastack/vegastack-labs/internal/backup", "github.com/vegastack/vegastack-labs/internal/change", "github.com/vegastack/vegastack-labs/internal/failure", "github.com/vegastack/vegastack-labs/internal/generated", "github.com/vegastack/vegastack-labs/internal/hostaction", "github.com/vegastack/vegastack-labs/internal/hostreplacement", "github.com/vegastack/vegastack-labs/internal/identity", "github.com/vegastack/vegastack-labs/internal/linuxrole", "github.com/vegastack/vegastack-labs/internal/plan", "github.com/vegastack/vegastack-labs/internal/run", "github.com/vegastack/vegastack-labs/internal/store", "io", "path/filepath", "regexp", "sort", "strconv", "sync/atomic", "time"}, digest: "8dca51e1b2809814f586c1b395769118d1c43846dfc2167804f8dc2bd70dc6a7"}, "internal/hostaction|bundle.go,native_producer_bundle.go,native_receipt.go,native_receipt_linux.go,native_receipt_unix.go,once.go,pipe_unix.go,policy_unix.go,receipt_unix.go,recovery_payload.go,request.go,result.go": {imports: []string{"bufio", "bytes", "context", "crypto/ed25519", "crypto/sha256", "encoding/base64", "encoding/hex", "encoding/json", "github.com/vegastack/vegastack-labs/internal/failure", "github.com/vegastack/vegastack-labs/internal/generated", "github.com/vegastack/vegastack-labs/internal/strictjson", "golang.org/x/sys/unix", "io", "os", "path/filepath", "regexp", "strings", "sync", "time"}, digest: "4b1781b8cec5f2b020db09995b171060aca93df7a663ffc4d8a026ef75621695"},
	"internal/adapter/nativecredential|authority_linux.go,effective_policy_linux.go,encrypt_linux.go,inspect_linux.go,lifecycle_verifier_linux.go,loaded_observer.go,loaded_observer_linux.go,native_restart_linux.go,observation_linux.go,policy_check_linux.go,probe_linux.go,process_observer_linux.go,resolver_linux.go,systemd_linux.go,verify_recovery_linux.go": {imports: []string{"bytes", "context", "crypto/sha256", "crypto/subtle", "encoding/hex", "encoding/json", "errors", "fmt", "github.com/godbus/dbus/v5", "github.com/vegastack/vegastack-labs/internal/credentialref", "github.com/vegastack/vegastack-labs/internal/failure", "github.com/vegastack/vegastack-labs/internal/generated", "golang.org/x/sys/unix", "io", "os", "os/exec", "os/user", "path/filepath", "reflect", "regexp", "slices", "strconv", "strings", "syscall", "time"}, digest: "c067dd0b04d13035022942970653febf5ee0ed9b5ea0dacb6799f5292842ab01"},
	"internal/hostaction|bundle.go,native_producer_bundle.go,native_receipt.go,native_receipt_unix.go,native_receipt_unsupported.go,once.go,pipe_unix.go,policy_unix.go,receipt_unix.go,recovery_payload.go,request.go,result.go":                                                                                                                                      {imports: []string{"bufio", "bytes", "context", "crypto/ed25519", "crypto/sha256", "encoding/base64", "encoding/hex", "encoding/json", "github.com/vegastack/vegastack-labs/internal/failure", "github.com/vegastack/vegastack-labs/internal/generated", "github.com/vegastack/vegastack-labs/internal/strictjson", "golang.org/x/sys/unix", "io", "os", "path/filepath", "regexp", "strings", "sync", "time"}, digest: "10e6363922976b3bcc4a084efa8ccd2f6b5b728a3c4e0ab2f64d2942837e3c1c"},
	"internal/adapter/nativecredential|loaded_observer.go": {imports: []string{"context", "errors", "github.com/vegastack/vegastack-labs/internal/credentialref"}, digest: "0728e42adc1f0d2e805290e6d569b1e6934ebe53845094011e4ab499aab84a58"},
	"internal/hostaction|bundle.go,native_producer_bundle.go,native_receipt.go,native_receipt_unsupported.go,once.go,pipe_other.go,platform_unsupported.go,recovery_payload.go,request.go,result.go": {imports: []string{"bufio", "context", "crypto/ed25519", "crypto/sha256", "encoding/base64", "encoding/hex", "encoding/json", "github.com/vegastack/vegastack-labs/internal/failure", "github.com/vegastack/vegastack-labs/internal/generated", "github.com/vegastack/vegastack-labs/internal/strictjson", "io", "os", "time"}, digest: "4936a886e4092bd26bfe947fd202d5403f69734c13b5594ac49af88e4996081d"},
}

func reviewedPhase228Package(c checkedSourcePackage, module, relative string) bool {
	if c.listed.ImportPath != module+"/"+relative || len(c.listed.CgoFiles) != 0 {
		return false
	}
	names := append([]string(nil), c.listed.GoFiles...)
	sort.Strings(names)
	seal, ok := phase228SourceSeals[relative+"|"+strings.Join(names, ",")]
	if !ok {
		return false
	}
	imports := append([]string(nil), c.listed.Imports...)
	sort.Strings(imports)
	expected := append([]string(nil), seal.imports...)
	for i, name := range expected {
		expected[i] = strings.Replace(name, "github.com/vegastack/vegastack-labs/", module+"/", 1)
	}
	sort.Strings(expected)
	return strings.Join(imports, "\x00") == strings.Join(expected, "\x00") && digestSourceFiles(c.listed.Dir, names) == seal.digest
}

const reviewedMainCompositionDigest = "f029c8f3e41b0f66ee2984d971d5d35735a456a60d36fcae6c07ca8ff64ef2d3"
const reviewedMainNativeLinuxDigest = "aabc6268605a8c4418b632d36247aa88071e4b024b76c71259e27c3f72a232fb"
const reviewedMainNativeOtherDigest = "9637bd3d4b8bcffb7f66d6e053263af9b97194432feebc4c513f280a9e910e78"

func reviewedMainComposition(candidate checkedSourcePackage, modulePath, cliImport, clientFileImport, releaseImport, serverImport string) bool {
	if reviewedPhase228Package(candidate, modulePath, "cmd/vsk-labs") {
		return true
	}
	if reviewedHostActionPackage(candidate, modulePath, "cmd/vsk-labs") {
		return true
	}
	approvedInternal := map[string]bool{
		modulePath + "/internal/backup":                   true,
		modulePath + "/internal/adapter/nativecredential": true,
		cliImport:                       true,
		clientFileImport:                true,
		releaseImport:                   true,
		modulePath + "/internal/result": true,
		serverImport:                    true,
	}
	extendedComposition := false
	for _, imported := range candidate.listed.Imports {
		if strings.HasPrefix(imported, modulePath+"/") {
			if !approvedInternal[imported] {
				return false
			}
			if imported != cliImport {
				extendedComposition = true
			}
		}
	}
	if !extendedComposition {
		return true
	}
	names := append([]string(nil), candidate.listed.GoFiles...)
	sort.Strings(names)
	digest := digestSourceFiles(candidate.listed.Dir, names)
	if containsString(names, "native_probe_linux.go") {
		return digest == reviewedMainNativeLinuxDigest
	}
	if containsString(names, "native_probe_unsupported.go") {
		return digest == reviewedMainNativeOtherDigest
	}
	return digest == reviewedMainCompositionDigest
}

func standardNetworkClosure(packages []listedPackage) map[string]bool {
	standard := make(map[string]listedPackage)
	for _, candidate := range packages {
		if candidate.Standard {
			standard[candidate.ImportPath] = candidate
		}
	}
	capable := map[string]bool{"net": true}
	for changed := true; changed; {
		changed = false
		for importPath, candidate := range standard {
			if capable[importPath] {
				continue
			}
			for _, imported := range candidate.Imports {
				if capable[imported] {
					capable[importPath] = true
					changed = true
					break
				}
			}
		}
	}
	return capable
}

func reviewedControlNetworkImport(candidate checkedSourcePackage, imported, mainImport, localAPIImport, localTransportImport, sshTransportImport, serverConfigImport string) bool {
	switch candidate.listed.ImportPath {
	case mainImport:
		return imported == "syscall" && reviewedMainSyscallUse(candidate)
	case localAPIImport:
		return imported == "net" && reviewedLocalAPISource(candidate)
	case strings.TrimSuffix(localAPIImport, "/internal/localapi") + "/internal/adapter/recoverydenial":
		if reviewedRecoveryDenialVerificationPackage(candidate, strings.TrimSuffix(localAPIImport, "/internal/localapi")) {
			return true
		}
		return false
	case localTransportImport:
		return (imported == "net" || imported == "net/http") && reviewedLocalTransportPackage(candidate)
	case sshTransportImport:
		return imported == "net/http" && reviewedSSHTransportPackage(candidate, localTransportImport)
	case serverConfigImport:
		return (imported == "net/url" || imported == "net/netip") && reviewedControlPlatformSource(candidate, "serverconfig")
	default:
		return false
	}
}

func reviewedMainSyscallUse(candidate checkedSourcePackage) bool {
	valid := true
	for _, file := range candidate.files {
		ast.Inspect(file, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			function, ok := candidate.info.ObjectOf(selector.Sel).(*types.Func)
			if ok && function.Pkg() != nil && function.Pkg().Path() == "syscall" {
				valid = false
				return false
			}
			return true
		})
	}
	return valid
}

func reviewedControlExternalImport(candidate checkedSourcePackage, imported string, standard bool, modulePath, localAPIImport, clientFileImport, serverConfigImport, releaseImport string) bool {
	if strings.HasPrefix(imported, modulePath+"/") || standard {
		return true
	}
	candidatePath := candidate.listed.ImportPath
	if candidatePath == localAPIImport && imported == "golang.org/x/sys/unix" && reviewedLocalAPISource(candidate) {
		return true
	}
	if candidatePath == clientFileImport && (imported == "golang.org/x/sys/unix" || imported == "golang.org/x/sys/windows") && reviewedControlPlatformSource(candidate, "clientfile") {
		return true
	}
	if candidatePath == serverConfigImport && imported == "golang.org/x/sys/unix" && reviewedControlPlatformSource(candidate, "serverconfig") {
		return true
	}
	if candidatePath == modulePath+"/internal/recovery" && imported == "golang.org/x/sys/unix" && reviewedRecoveryCustodianPackage(candidate) {
		return true
	}
	if candidatePath == releaseImport {
		switch imported {
		case "github.com/sigstore/sigstore-go/pkg/bundle", "github.com/sigstore/sigstore-go/pkg/root", "github.com/sigstore/sigstore-go/pkg/verify":
			return true
		}
	}
	return false
}

func reviewedControlPlatformSource(candidate checkedSourcePackage, kind string) bool {
	if kind == "serverconfig" && reviewedHostActionPackage(candidate, strings.TrimSuffix(candidate.listed.ImportPath, "/internal/serverconfig"), "internal/serverconfig") {
		return true
	}
	names := append([]string(nil), candidate.listed.GoFiles...)
	sort.Strings(names)
	var expected string
	switch kind {
	case "clientfile":
		expected = "20cf2e7ef6da35560d59b88a69e75391ae58b22a22d88da619000e019adaf28b"
		if containsString(names, "read_unix.go") {
			expected = "20230c50a5ab877241ef447281ade07e836298d3cde4f85d187b304f35aafae2"
		}
	case "serverconfig":
		expected = "26841031a8b95b00313f85233d083c2d715541152a97aba3bb5b9d7337d080a7"
		if containsString(names, "profile_linux.go") {
			expected = "de8446d73d62ec36f3b33baff9eeff3f5e0c4d17f8902466fb3c6e63865813d1"
		}
	default:
		return false
	}
	digest := digestSourceFiles(candidate.listed.Dir, names)
	if digest == expected {
		return true
	}
	// #231 adds only frozen-byte DecodeProfile; retain historical snapshots above.
	if kind == "serverconfig" {
		switch strings.Join(names, ",") {
		case "profile.go,profile_linux.go,restic.go":
			return digest == "c1dc99d73c31551abfa5ff6100167837b4d14329bc97def48f6360d0de5d40c8"
		case "profile.go,profile_unsupported.go,restic.go":
			return digest == "b04d95ce7a72e5718b87bc8d3e95be2daf3590c7222567d6271bb9ec9e60b2f8"
		}
	}
	return false
}

func moduleDependencyClosure(packages []listedPackage, root string) map[string]bool {
	return moduleDependencyClosurePruned(packages, root, nil)
}

func moduleDependencyClosurePruned(packages []listedPackage, root string, stop map[string]bool) map[string]bool {
	byImport := make(map[string]listedPackage, len(packages))
	for _, candidate := range packages {
		byImport[candidate.ImportPath] = candidate
	}
	if _, ok := byImport[root]; !ok {
		return nil
	}
	closure := make(map[string]bool)
	pending := []string{root}
	for len(pending) > 0 {
		current := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		if closure[current] {
			continue
		}
		closure[current] = true
		if stop[current] {
			continue
		}
		for _, imported := range byImport[current].Imports {
			if _, ok := byImport[imported]; ok {
				pending = append(pending, imported)
			}
		}
	}
	return closure
}

func reviewedLocalClientDependencies(closure map[string]bool, modulePath, localAPIImport, localTransportImport, sshTransportImport string) bool {
	approved := map[string]bool{
		localAPIImport:                          true,
		localTransportImport:                    true,
		sshTransportImport:                      true,
		modulePath + "/internal/apissh":         true,
		modulePath + "/internal/credentialref":  true,
		modulePath + "/internal/backupidentity": true,
		modulePath + "/internal/failure":        true,
		modulePath + "/internal/generated":      true,
		modulePath + "/internal/principal":      true,
		modulePath + "/internal/result":         true,
		modulePath + "/internal/runprotocol":    true,
		modulePath + "/internal/serverconfig":   true,
		modulePath + "/internal/strictjson":     true,
		modulePath + "/internal/hostaction":     true,
	}
	for importPath := range closure {
		if !approved[importPath] {
			return false
		}
	}
	return true
}

func reviewedLocalClientPackage(candidate checkedSourcePackage, modulePath, localAPIImport, localTransportImport, sshTransportImport string) bool {
	if candidate.listed.ImportPath == modulePath+"/internal/hostaction" {
		return reviewedPhase228Package(candidate, modulePath, "internal/hostaction")
	}
	approvedExternal := func(imported string) bool {
		return imported == "golang.org/x/sys/unix" || imported == "github.com/go-jose/go-jose/v4" || imported == "github.com/go-jose/go-jose/v4/jwt"
	}
	if candidate.listed.ImportPath == localTransportImport {
		return reviewedLocalTransportPackage(candidate)
	}
	if candidate.listed.ImportPath == sshTransportImport {
		return reviewedSSHTransportPackage(candidate, localTransportImport)
	}
	// The backup identity registry is portable constant/data logic shared with
	// serverconfig. It has no imports or runtime capability of its own.
	if candidate.listed.ImportPath == modulePath+"/internal/backupidentity" {
		return len(candidate.listed.Imports) == 0
	}
	if candidate.listed.ImportPath != localAPIImport {
		for _, imported := range candidate.listed.Imports {
			if imported == "os/exec" || imported == "plugin" || imported == "database/sql" {
				return false
			}
			if !strings.HasPrefix(imported, modulePath+"/") && strings.Contains(imported, ".") && !approvedExternal(imported) {
				return false
			}
		}
		return true
	}
	if !reviewedLocalAPISource(candidate) {
		return false
	}
	for _, imported := range candidate.listed.Imports {
		if imported == "os/exec" || imported == "plugin" || imported == "database/sql" || imported == "net/http" || imported == "net/url" || imported == "crypto/tls" || imported == "reflect" || imported == "unsafe" || imported == "syscall" {
			return false
		}
		if strings.HasPrefix(imported, modulePath+"/") || !strings.Contains(imported, ".") || approvedExternal(imported) {
			continue
		}
		// The reviewed local client has no third-party dependency. Provider SDKs
		// and any future external transport must pass a separate design review.
		return false
	}
	approvedCallbacks := reviewedLocalCallbacks(candidate)
	valid := true
	for _, file := range candidate.files {
		directCallees := make(map[ast.Expr]bool)
		ast.Inspect(file, func(node ast.Node) bool {
			if call, ok := node.(*ast.CallExpr); ok {
				directCallees[unparenthesized(call.Fun)] = true
			}
			return true
		})
		ast.Inspect(file, func(node ast.Node) bool {
			if !valid {
				return false
			}
			if selector, ok := node.(*ast.SelectorExpr); ok {
				function, functionOK := candidate.info.ObjectOf(selector.Sel).(*types.Func)
				if functionOK && function.Pkg() != nil && reviewedNetworkFunctionPackage(function.Pkg().Path()) && !directCallees[unparenthesized(selector)] {
					valid = false
					return false
				}
			}
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			if variable := calledFunctionVariable(call.Fun, candidate.info); variable != nil {
				if !reviewedLocalCallbackCall(call.Fun, variable, candidate.info, localAPIImport, approvedCallbacks) {
					valid = false
					return false
				}
				return true
			}
			function := calledFunction(call.Fun, candidate.info)
			if function == nil {
				callee := unparenthesized(call.Fun)
				if identifier, ok := callee.(*ast.Ident); ok {
					if _, builtin := candidate.info.ObjectOf(identifier).(*types.Builtin); builtin {
						return true
					}
				}
				if _, literal := callee.(*ast.FuncLit); !literal {
					if functionType := candidate.info.TypeOf(callee); functionType != nil {
						if _, indirect := types.Unalias(functionType).Underlying().(*types.Signature); indirect {
							valid = false
							return false
						}
					}
				}
				return true
			}
			if function.Pkg() == nil {
				return true
			}
			switch function.Pkg().Path() {
			case "net":
				valid = reviewedUnixDial(function, call)
			case "net/http", "net/url", "crypto/tls":
				valid = false
			}
			return valid
		})
	}
	return valid
}

const (
	reviewedLocalAPILinuxDigest       = "23c1b6e73ff1ae5fe910966e936571711e348b96382669604c57445fc4d98b7d"
	reviewedLocalAPIUnsupportedDigest = "50ca54e99992f1651e315421510f408df189f0290569cd2f91665b6038e82272"
	// #104 adds one typed gate client to the original reviewed package; these
	// wave digests are separate from, and do not replace, the baseline goldens.
	reviewedGateLocalAPILinuxDigest       = "bbeb263e7cfba9102961e338cc51c0fdbc364bf20e472adf85ef135658681e06"
	reviewedGateLocalAPIUnsupportedDigest = "d03ab3381a723be7e6b4027164e00c6d2723d8fae8e3c6a7da4690b5834999e4"
	// #124 adds the one bounded local binary credential-import method. These
	// exact package seals do not authorize another method, transport or target.
	reviewedCredentialImportLocalAPILinuxDigest       = "8697120933958c3b2b47a9b6e8095e723d45dec8ed297c60a6f1f23d8e5660d7"
	reviewedCredentialImportLocalAPIUnsupportedDigest = "bda08c1a3c877f6fa353aa6fd6d73e05076b759c710eac8df95a6d1e488bed88"
	// #107 adds typed audit checkpoint and verification reads without adding a
	// transport escape hatch. The audit and credential-import clients now coexist
	// in the production package, so its byte-for-byte seal is the combined closure
	// of both waves over the current sources.
	reviewedAuditCredentialLocalAPILinuxDigest       = "a0fa1ad5845527ea5bba96709e3e6f0c81528fc6cb77823733666850a8c53812"
	reviewedAuditCredentialLocalAPIUnsupportedDigest = "c4a5a8bddeb0579d7dbd537c248836c92fa98fe4ac52fd77dccae7a47d7867d4"
	reviewedScheduleLocalAPILinuxDigest              = "296ae54aa9e5e5554f33d82371105acb286f2c72c74ed0d39183e869db055dfd"
	reviewedScheduleLocalAPIUnsupportedDigest        = "e1db57ef9e23a3bd1068e0ac42189edac917a44b0842d207abb3717933ca3d49"
	// #110 adds typed database-scoped aliases over the reviewed backup and
	// restore routes plus one inert export-draft route. The complete package
	// remains sealed so the new file cannot widen the local transport.
	reviewedDatabaseLocalAPILinuxDigest       = "d3bafb206d235c6da669ed04e540d419f2cacddfd00a805010b95a71c3a70806"
	reviewedDatabaseLocalAPIUnsupportedDigest = "9bdeff75e774242bde84220094b3b4d08f49c26451e363548e04e5b5a1f22fdd"
)

// reviewedLocalAPISource seals every production source file in the package
// that can reach the value-only local transport. This makes caller provenance
// part of the reviewed boundary: adding a raw forwarding helper, a new client
// method, an init hook, a target-specific file, or a syscall path fails closed
// until the complete package is independently reviewed and resealed.

// #232 extends only the exact typed host client closure.
const (
	reviewedHostLocalAPILinuxDigest       = "e38e9b31ada27afc4f08bb33b82d375ca1fcdd4c58b8e00fd4e9fe3bee3eaab7"
	reviewedHostLocalAPIUnsupportedDigest = "4710ccbccede43377e03b93bba6124fbd288661ff7ccd3806798e570daff092f"
)

func reviewedLocalAPISource(candidate checkedSourcePackage) bool {
	if reviewedPhase228Package(candidate, strings.TrimSuffix(candidate.listed.ImportPath, "/internal/localapi"), "internal/localapi") {
		return true
	}
	if reviewedHostWorkflowPackage(candidate, strings.TrimSuffix(candidate.listed.ImportPath, "/internal/localapi"), "internal/localapi") || reviewedLinuxRolePackage(candidate, strings.TrimSuffix(candidate.listed.ImportPath, "/internal/localapi"), "internal/localapi") {
		return true
	}
	names := append([]string(nil), candidate.listed.GoFiles...)
	sort.Strings(names)
	expected := reviewedLocalAPIUnsupportedDigest
	if containsString(names, "listener_linux.go") {
		expected = reviewedLocalAPILinuxDigest
	}
	if containsString(names, "gates_client.go") && !containsString(names, "credential_client.go") && !containsString(names, "audit_client.go") {
		if containsString(names, "listener_linux.go") {
			if strings.Join(names, ",") != "client.go,gates_client.go,listener.go,listener_linux.go" {
				return false
			}
			expected = reviewedGateLocalAPILinuxDigest
		} else {
			if strings.Join(names, ",") != "client.go,gates_client.go,listener.go,listener_unsupported.go" {
				return false
			}
			expected = reviewedGateLocalAPIUnsupportedDigest
		}
	}
	if containsString(names, "credential_client.go") && !containsString(names, "audit_client.go") {
		if containsString(names, "listener_linux.go") {
			if strings.Join(names, ",") != "client.go,credential_client.go,gates_client.go,listener.go,listener_linux.go" {
				return false
			}
			expected = reviewedCredentialImportLocalAPILinuxDigest
		} else {
			if strings.Join(names, ",") != "client.go,credential_client.go,gates_client.go,listener.go,listener_unsupported.go" {
				return false
			}
			expected = reviewedCredentialImportLocalAPIUnsupportedDigest
		}
	}
	if containsString(names, "audit_client.go") && containsString(names, "credential_client.go") && !containsString(names, "backup_client.go") && !containsString(names, "credential_lifecycle_client.go") {
		if containsString(names, "listener_linux.go") {
			if strings.Join(names, ",") != "audit_client.go,client.go,credential_client.go,gates_client.go,listener.go,listener_linux.go" {
				return false
			}
			expected = reviewedAuditCredentialLocalAPILinuxDigest
		} else {
			if strings.Join(names, ",") != "audit_client.go,client.go,credential_client.go,gates_client.go,listener.go,listener_unsupported.go" {
				return false
			}
			expected = reviewedAuditCredentialLocalAPIUnsupportedDigest
		}
	}
	if containsString(names, "backup_client.go") && containsString(names, "credential_lifecycle_client.go") {
		withRestore := containsString(names, "restore_client.go")
		withSchedule := containsString(names, "schedule_client.go")
		withDatabase := containsString(names, "database_client.go")
		withHosts := containsString(names, "hosts_client.go")
		if containsString(names, "listener_linux.go") {
			exact := "audit_client.go,backup_client.go,client.go,credential_client.go,credential_lifecycle_client.go,gates_client.go,listener.go,listener_linux.go"
			if withRestore {
				exact += ",restore_client.go"
			}
			if withSchedule {
				exact += ",schedule_client.go"
			}
			if withDatabase {
				exact = "audit_client.go,backup_client.go,client.go,credential_client.go,credential_lifecycle_client.go,database_client.go,gates_client.go,listener.go,listener_linux.go,restore_client.go,schedule_client.go"
			}
			if withHosts {
				exact = strings.Replace(exact, "gates_client.go,", "gates_client.go,hosts_client.go,", 1)
			}
			if strings.Join(names, ",") != exact {
				return false
			}
			expected = reviewedBackupLifecycleLocalAPILinuxDigest
			if withRestore {
				expected = reviewedRestoreLocalAPILinuxDigest
			}
			if withSchedule {
				expected = reviewedScheduleLocalAPILinuxDigest
			}
			if withDatabase {
				expected = reviewedDatabaseLocalAPILinuxDigest
				if withHosts {
					expected = reviewedHostLocalAPILinuxDigest
				}
			}
		} else {
			exact := "audit_client.go,backup_client.go,client.go,credential_client.go,credential_lifecycle_client.go,gates_client.go,listener.go,listener_unsupported.go"
			if withRestore {
				exact += ",restore_client.go"
			}
			if withSchedule {
				exact += ",schedule_client.go"
			}
			if withDatabase {
				exact = "audit_client.go,backup_client.go,client.go,credential_client.go,credential_lifecycle_client.go,database_client.go,gates_client.go,listener.go,listener_unsupported.go,restore_client.go,schedule_client.go"
			}
			if withHosts {
				exact = strings.Replace(exact, "gates_client.go,", "gates_client.go,hosts_client.go,", 1)
			}
			if strings.Join(names, ",") != exact {
				return false
			}
			expected = reviewedBackupLifecycleLocalAPIUnsupportedDigest
			if withRestore {
				expected = reviewedRestoreLocalAPIUnsupportedDigest
			}
			if withSchedule {
				expected = reviewedScheduleLocalAPIUnsupportedDigest
			}
			if withDatabase {
				expected = reviewedDatabaseLocalAPIUnsupportedDigest
				if withHosts {
					expected = reviewedHostLocalAPIUnsupportedDigest
				}
			}
		}
	} else if containsString(names, "backup_client.go") {
		if containsString(names, "listener_linux.go") {
			if strings.Join(names, ",") != "audit_client.go,backup_client.go,client.go,credential_client.go,gates_client.go,listener.go,listener_linux.go" {
				return false
			}
			expected = reviewedBackupLocalAPILinuxDigest
		} else {
			if strings.Join(names, ",") != "audit_client.go,backup_client.go,client.go,credential_client.go,gates_client.go,listener.go,listener_unsupported.go" {
				return false
			}
			expected = reviewedBackupLocalAPIUnsupportedDigest
		}
	} else if containsString(names, "credential_lifecycle_client.go") {
		if containsString(names, "listener_linux.go") {
			if strings.Join(names, ",") != "audit_client.go,client.go,credential_client.go,credential_lifecycle_client.go,gates_client.go,listener.go,listener_linux.go" {
				return false
			}
			expected = "0b49c511c5450421d8a043d865dffd8ac9a36e4fe646dd1263d0ea75af995515"
		} else {
			if strings.Join(names, ",") != "audit_client.go,client.go,credential_client.go,credential_lifecycle_client.go,gates_client.go,listener.go,listener_unsupported.go" {
				return false
			}
			expected = "f4e3a49d5912730d1266ef549c344763e7632b400474aebd4c2d69e754334570"
		}
	}
	return digestSourceFiles(candidate.listed.Dir, names) == expected
}

const (
	// #118 adds one typed off-site retirement staging request. It carries only
	// public IDs/digests and reaches the existing value-only local transport.
	reviewedBackupLifecycleLocalAPILinuxDigest       = "c60cbea77d5c0c5e5b93c0739b56db12fe036fcd419c103398bc485be54d61b1"
	reviewedBackupLifecycleLocalAPIUnsupportedDigest = "0e2035a66bcd51711c67e21ec3f3326783429defaeb6c0628b16f33fc488feb4"
	reviewedBackupLocalAPILinuxDigest                = "9341e73b56a727fdf9b64e013fcd43f3c896e786c20c8e9a7c087429abbb193c"
	reviewedBackupLocalAPIUnsupportedDigest          = "6119851667da72ab447af607b2f0aa9e2b5e5345c4fccf84a3b4fdf898bb08f1"
	// #108's restore client and #118's off-site retirement methods coexist in
	// the exact production local-API package closure.
	reviewedRestoreLocalAPILinuxDigest       = "cb0e80e6804accb26d094e7a562fb7ce131cdb5162874b84ee814ea84e85a52e"
	reviewedRestoreLocalAPIUnsupportedDigest = "bbf72e785c3b17d1f62d6b49848f540b92a12e1928c8166ba5eff3c102ddb466"
)

const reviewedAuditVerificationDigest = "1f4068a1ea9ee0eb52ab91fd5b792b9d094218a50b5ba6fc4e74568d70bc07b8"

func reviewedAuditVerificationPackage(candidate checkedSourcePackage) bool {
	names := append([]string(nil), candidate.listed.GoFiles...)
	sort.Strings(names)
	if strings.Join(names, ",") != "canonical.go,chain.go,checkpoint.go,types.go,verify.go" {
		return false
	}
	return digestSourceFiles(candidate.listed.Dir, names) == reviewedAuditVerificationDigest
}

// The recovery-denial adapter verifies observer signatures with public
// material. Seal the complete implementation and continue rejecting every
// Ed25519 private-key operation outside the recovery custodian collector.
func reviewedRecoveryDenialVerificationPackage(candidate checkedSourcePackage, modulePath string) bool {
	if candidate.listed.ImportPath != modulePath+"/internal/adapter/recoverydenial" {
		return false
	}
	names := append([]string(nil), candidate.listed.GoFiles...)
	sort.Strings(names)
	if strings.Join(names, ",") != "https.go,types.go" || digestSourceFiles(candidate.listed.Dir, names) != "ef6e0c94a0fdd174dc279eb1c6cec75e9d2f23c89cfe93744f445c882564b973" {
		return false
	}
	for _, file := range candidate.files {
		forbidden := false
		ast.Inspect(file, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if ok {
				if object := candidate.info.ObjectOf(selector.Sel); object != nil && object.Pkg() != nil && object.Pkg().Path() == "crypto/ed25519" {
					switch object.Name() {
					case "Sign", "GenerateKey", "NewKeyFromSeed", "PrivateKey":
						forbidden = true
					}
				}
			}
			return !forbidden
		})
		if forbidden {
			return false
		}
	}
	return true
}

func reviewedRecoveryCanaryVerificationFile(candidate checkedSourcePackage, serverImport string) bool {
	if candidate.listed.ImportPath != serverImport || !containsString(candidate.listed.GoFiles, "recovery_canary_system.go") || digestSourceFiles(candidate.listed.Dir, []string{"recovery_canary_system.go"}) != "e5c6b4c0135eccca2e07f4a981bd2a33b93cee22894bfbbdc1b989a86f72c8ef" {
		return false
	}
	for _, file := range candidate.files {
		if filepath.Base(candidate.listed.Dir) != "server" {
			return false
		}
		forbidden := false
		ast.Inspect(file, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if ok {
				if object := candidate.info.ObjectOf(selector.Sel); object != nil && object.Pkg() != nil && object.Pkg().Path() == "crypto/ed25519" {
					switch object.Name() {
					case "Sign", "GenerateKey", "NewKeyFromSeed", "PrivateKey":
						forbidden = true
					}
				}
			}
			return !forbidden
		})
		if forbidden {
			return false
		}
	}
	return true
}

// The recovery contract verifies independently signed public artifacts. It
// never holds an Ed25519 signing key or signs state in the controller. Keep
// both platform source sets pinned and reject signing references explicitly.
func reviewedRecoveryVerificationPackage(candidate checkedSourcePackage) bool {
	names := append([]string(nil), candidate.listed.GoFiles...)
	sort.Strings(names)
	var expected string
	switch strings.Join(names, ",") {
	case "artifact.go,custody.go,fence_witness.go,manifest.go,manifest_file_unix.go,receipt_file_unix.go,transport.go,witness.go":
		expected = "0323065bcb35a55d999e271be1330abc1453ad5160436e3bb6ef2eb5074aece6"
	case "artifact.go,custody.go,fence_witness.go,manifest.go,manifest_file_unsupported.go,receipt_file_unsupported.go,transport.go,witness.go":
		expected = "1232ac61b79bc15df35c6fc6b6f09929d68792249e785ccd4faeeaa29d2aa402"
	default:
		return false
	}
	if digestSourceFiles(candidate.listed.Dir, names) != expected {
		return false
	}
	for _, name := range names {
		file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(candidate.listed.Dir, name), nil, parser.ImportsOnly)
		if err != nil {
			return false
		}
		alias := ""
		for _, imported := range file.Imports {
			path, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				return false
			}
			if path == "crypto/ed25519" {
				alias = "ed25519"
				if imported.Name != nil {
					alias = imported.Name.Name
				}
				if alias == "." {
					return false
				}
			}
		}
		if alias == "" || alias == "_" {
			continue
		}
		file, err = parser.ParseFile(token.NewFileSet(), filepath.Join(candidate.listed.Dir, name), nil, 0)
		if err != nil {
			return false
		}
		forbidden := false
		ast.Inspect(file, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			identifier, ok := selector.X.(*ast.Ident)
			if ok && identifier.Name == alias {
				switch selector.Sel.Name {
				case "Sign", "GenerateKey", "NewKeyFromSeed", "PrivateKey":
					forbidden = true
				}
			}
			return !forbidden
		})
		if forbidden {
			return false
		}
	}
	return true
}

// #153's finite custodian command signs only an exact independently pinned
// witness collection. This exception is confined to the complete reviewed
// recovery source set and the one collector file; any source drift fails the
// public-client analyzer closed until a fresh review reseals it.
// The server-side SSH read protocol is not a public CLI dispatch registry.
// Only its exact reviewed source may carry the fixed operation/command table.
func reviewedHostDiscoveryCollectorPackage(candidate checkedSourcePackage) bool {
	names := append([]string(nil), candidate.listed.GoFiles...)
	sort.Strings(names)
	return strings.Join(names, ",") == "collector.go,decode.go" &&
		digestSourceFiles(candidate.listed.Dir, names) == "ad72f458ac1e4c1752056b87fac0f75963e09442a5ae951c567da3092be88d72"
}

func reviewedRecoveryCustodianPackage(candidate checkedSourcePackage) bool {
	names := append([]string(nil), candidate.listed.GoFiles...)
	sort.Strings(names)
	currentReviewed := reviewedPhase228Package(candidate, strings.TrimSuffix(candidate.listed.ImportPath, "/internal/recovery"), "internal/recovery")
	var expected string
	switch strings.Join(names, ",") {
	case "artifact.go,audit_continuity.go,bound_canary_noop.go,canary.go,canary_capabilities.go,canary_ports.go,candidate.go,candidate_authority.go,candidate_destination.go,candidate_unsupported.go,collector.go,custody.go,fence.go,fence_admission.go,fence_coordinator.go,fence_evidence.go,fence_execution.go,fence_witness.go,host_generation_fence.go,host_replacement_continuity.go,manifest.go,manifest_file_unsupported.go,offsite_source.go,operations.go,package_file_unsupported.go,qualification.go,qualified_registry_unsupported.go,receipt_file_unsupported.go,source.go,source_admission.go,source_admission_file_unsupported.go,source_handoff.go,store_canary.go,store_operations.go,transport.go,witness.go":
		expected = "a9f0111f7fd9dada3193bdd279c897eac14394c87de24db11f4baff58c5c5c4a"
	case "artifact.go,audit_continuity.go,bound_canary_noop.go,canary.go,canary_capabilities.go,canary_ports.go,candidate.go,candidate_authority.go,candidate_destination.go,candidate_unsupported.go,collector.go,custody.go,fence.go,fence_admission.go,fence_coordinator.go,fence_evidence.go,fence_execution.go,fence_witness.go,host_generation_fence.go,host_replacement_continuity.go,manifest.go,manifest_file_unix.go,offsite_source.go,operations.go,package_file_unix.go,qualification.go,qualified_registry_unsupported.go,receipt_file_unix.go,source.go,source_admission.go,source_admission_file_unix.go,source_handoff.go,store_canary.go,store_operations.go,transport.go,witness.go":
		expected = "c2af328355d3164391fef7a55a592e5376207abf4cccd32fff404a577a1f7921"
	case "artifact.go,audit_continuity.go,bound_canary_noop.go,canary.go,canary_capabilities.go,canary_ports.go,candidate.go,candidate_authority.go,candidate_destination.go,candidate_destination_linux.go,candidate_linux.go,collector.go,custody.go,fence.go,fence_admission.go,fence_coordinator.go,fence_evidence.go,fence_execution.go,fence_witness.go,host_generation_fence.go,host_replacement_continuity.go,manifest.go,manifest_file_unix.go,offsite_source.go,operations.go,package_file_unix.go,qualification.go,qualified_registry_linux.go,receipt_file_unix.go,source.go,source_admission.go,source_admission_file_unix.go,source_handoff.go,store_canary.go,store_operations.go,transport.go,witness.go":
		expected = "a072e2086d029bd7c445a83468a6c8fc9c611ad7b6ef33fef2fae4a4d3c612a6"
	case "artifact.go,audit_continuity.go,bound_canary_noop.go,canary.go,canary_capabilities.go,canary_ports.go,candidate.go,candidate_authority.go,candidate_linux.go,collector.go,custody.go,fence.go,fence_admission.go,fence_coordinator.go,fence_evidence.go,fence_execution.go,fence_witness.go,host_generation_fence.go,host_replacement_continuity.go,manifest.go,manifest_file_unix.go,offsite_source.go,operations.go,package_file_unix.go,qualification.go,qualified_registry_linux.go,receipt_file_unix.go,source.go,source_admission.go,source_admission_file_unix.go,source_handoff.go,store_canary.go,store_operations.go,transport.go,witness.go":
		expected = "4398a3e37fbd9c262a9c5062fb62cd6607fa3237b54b18dbe8220de1e2308847"
	case "artifact.go,audit_continuity.go,bound_canary_noop.go,canary.go,canary_capabilities.go,canary_ports.go,candidate.go,candidate_authority.go,candidate_unsupported.go,collector.go,custody.go,fence.go,fence_admission.go,fence_coordinator.go,fence_evidence.go,fence_execution.go,fence_witness.go,host_generation_fence.go,host_replacement_continuity.go,manifest.go,manifest_file_unix.go,offsite_source.go,operations.go,package_file_unix.go,qualification.go,qualified_registry_unsupported.go,receipt_file_unix.go,source.go,source_admission.go,source_admission_file_unix.go,source_handoff.go,store_canary.go,store_operations.go,transport.go,witness.go":
		expected = "66aa2722e411026ddea10ad8d97ea2f537d823574be9d17c1833d4604a34927e"
	case "artifact.go,audit_continuity.go,bound_canary_noop.go,canary.go,canary_capabilities.go,canary_ports.go,candidate.go,candidate_authority.go,candidate_unsupported.go,collector.go,custody.go,fence.go,fence_admission.go,fence_coordinator.go,fence_evidence.go,fence_execution.go,fence_witness.go,host_generation_fence.go,host_replacement_continuity.go,manifest.go,manifest_file_unsupported.go,offsite_source.go,operations.go,package_file_unsupported.go,qualification.go,qualified_registry_unsupported.go,receipt_file_unsupported.go,source.go,source_admission.go,source_admission_file_unsupported.go,source_handoff.go,store_canary.go,store_operations.go,transport.go,witness.go":
		expected = "a918fcd6a6f76529d69ed63c4249644bd695c662f84eab41485d0cc1eea2a37a"
	case "artifact.go,audit_continuity.go,bound_canary_noop.go,canary.go,canary_capabilities.go,canary_ports.go,candidate.go,candidate_authority.go,candidate_linux.go,collector.go,custody.go,fence.go,fence_admission.go,fence_coordinator.go,fence_evidence.go,fence_execution.go,fence_witness.go,manifest.go,manifest_file_unix.go,offsite_source.go,operations.go,package_file_unix.go,qualification.go,qualified_registry_linux.go,receipt_file_unix.go,source.go,source_admission.go,source_admission_file_unix.go,source_handoff.go,store_canary.go,store_operations.go,transport.go,witness.go":
		expected = "f70716f4b4d84488770ba4b8cdcc36346fd23ab656983f6abae3d97576fbeaa9"
	case "artifact.go,audit_continuity.go,bound_canary_noop.go,canary.go,canary_capabilities.go,canary_ports.go,candidate.go,candidate_authority.go,candidate_unsupported.go,collector.go,custody.go,fence.go,fence_admission.go,fence_coordinator.go,fence_evidence.go,fence_execution.go,fence_witness.go,manifest.go,manifest_file_unix.go,offsite_source.go,operations.go,package_file_unix.go,qualification.go,qualified_registry_unsupported.go,receipt_file_unix.go,source.go,source_admission.go,source_admission_file_unix.go,source_handoff.go,store_canary.go,store_operations.go,transport.go,witness.go":
		expected = "0971b7c5344f9a2dc306b0794ba8a38b4b6deb3f6a27849614a9ba89d88ec0c6"
	case "artifact.go,audit_continuity.go,bound_canary_noop.go,canary.go,canary_capabilities.go,canary_ports.go,candidate.go,candidate_authority.go,candidate_unsupported.go,collector.go,custody.go,fence.go,fence_admission.go,fence_coordinator.go,fence_evidence.go,fence_execution.go,fence_witness.go,manifest.go,manifest_file_unsupported.go,offsite_source.go,operations.go,package_file_unsupported.go,qualification.go,qualified_registry_unsupported.go,receipt_file_unsupported.go,source.go,source_admission.go,source_admission_file_unsupported.go,source_handoff.go,store_canary.go,store_operations.go,transport.go,witness.go":
		expected = "60953df99739a99e33495a408772a4a6c28f137bf69b1e3e2ab9baf34eb6aa6c"
	default:
		if !currentReviewed {
			return false
		}
	}
	if !currentReviewed && digestSourceFiles(candidate.listed.Dir, names) != expected {
		return false
	}
	for _, name := range names {
		if name == "collector.go" {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(candidate.listed.Dir, name), nil, 0)
		if err != nil {
			return false
		}
		privateUse := false
		ast.Inspect(file, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			identifier, ok := selector.X.(*ast.Ident)
			if ok && identifier.Name == "ed25519" {
				switch selector.Sel.Name {
				case "Sign", "GenerateKey", "NewKeyFromSeed", "PrivateKey":
					privateUse = true
				}
			}
			return !privateUse
		})
		if privateUse {
			return false
		}
	}
	return true
}

func reviewedNetworkFunctionPackage(packagePath string) bool {
	switch packagePath {
	case "net", "net/http", "net/url", "crypto/tls":
		return true
	default:
		return false
	}
}

func reviewedLocalCallbackCall(expression ast.Expr, variable *types.Var, info *types.Info, localAPIImport string, approved map[*types.Var]bool) bool {
	if approved[variable] {
		return true
	}
	selector, ok := unparenthesized(expression).(*ast.SelectorExpr)
	return ok && variable.IsField() && variable.Name() == "onClose" && typeNamed(info.TypeOf(selector.X), localAPIImport, "authenticatedConn")
}

func typeNamed(value types.Type, packagePath, name string) bool {
	for {
		value = types.Unalias(value)
		pointer, ok := value.(*types.Pointer)
		if !ok {
			break
		}
		value = pointer.Elem()
	}
	named, ok := value.(*types.Named)
	return ok && named.Obj() != nil && named.Obj().Pkg() != nil && named.Obj().Pkg().Path() == packagePath && named.Obj().Name() == name
}

func calledFunctionVariable(expression ast.Expr, info *types.Info) *types.Var {
	var object types.Object
	switch typed := unparenthesized(expression).(type) {
	case *ast.Ident:
		object = info.ObjectOf(typed)
	case *ast.SelectorExpr:
		object = info.ObjectOf(typed.Sel)
	}
	variable, ok := object.(*types.Var)
	if !ok {
		return nil
	}
	if _, ok := types.Unalias(variable.Type()).Underlying().(*types.Signature); !ok {
		return nil
	}
	return variable
}

// reviewedLocalCallbacks names the three function values required by the
// socket implementation and binds them to their exact declarations. A caller
// cannot evade the network guard by reusing one of these names in another
// scope or by assigning a package function to a local variable.
func reviewedLocalCallbacks(candidate checkedSourcePackage) map[*types.Var]bool {
	approved := make(map[*types.Var]bool)
	for _, file := range candidate.files {
		ast.Inspect(file, func(node ast.Node) bool {
			switch typed := node.(type) {
			case *ast.FuncDecl:
				// #228's exact bound-apply validator is a local pure closure,
				// called again when inspecting an uncertain ordinary run.
				if typed.Name.Name == "ApplyBound" && typed.Body != nil && reviewedPhase228Package(candidate, strings.TrimSuffix(candidate.listed.ImportPath, "/internal/localapi"), "internal/localapi") {
					ast.Inspect(typed.Body, func(node ast.Node) bool {
						statement, ok := node.(*ast.AssignStmt)
						if !ok || statement.Tok != token.DEFINE || len(statement.Lhs) != 1 || len(statement.Rhs) != 1 {
							return true
						}
						name, ok := statement.Lhs[0].(*ast.Ident)
						if !ok || name.Name != "valid" {
							return true
						}
						if _, ok := statement.Rhs[0].(*ast.FuncLit); !ok {
							return true
						}
						if variable, ok := candidate.info.Defs[name].(*types.Var); ok {
							approved[variable] = true
						}
						return true
					})
				}
				parameter := ""
				switch typed.Name.Name {
				case "validateTypedResponse", "databaseRequest":
					parameter = "validate"
				case "newAuthenticatedConn":
					parameter = "onClose"
				}
				if parameter != "" && typed.Type.Params != nil {
					for _, field := range typed.Type.Params.List {
						for _, name := range field.Names {
							if name.Name == parameter {
								if variable, ok := candidate.info.Defs[name].(*types.Var); ok {
									approved[variable] = true
								}
							}
						}
					}
				}
			case *ast.AssignStmt:
				if len(typed.Lhs) != 2 || len(typed.Rhs) != 1 {
					return true
				}
				call, ok := unparenthesized(typed.Rhs[0]).(*ast.CallExpr)
				if !ok {
					return true
				}
				function := calledFunction(call.Fun, candidate.info)
				if function == nil || function.Pkg() == nil || function.Pkg().Path() != "context" || function.Name() != "WithTimeout" {
					return true
				}
				name, ok := unparenthesized(typed.Lhs[1]).(*ast.Ident)
				if !ok {
					return true
				}
				object := candidate.info.ObjectOf(name)
				if variable, ok := object.(*types.Var); ok {
					approved[variable] = true
				}
			}
			return true
		})
	}
	return approved
}

func reviewedUnixDial(function *types.Func, call *ast.CallExpr) bool {
	switch function.Name() {
	case "DialContext":
		if len(call.Args) != 3 {
			return false
		}
		signature, ok := function.Type().(*types.Signature)
		if !ok || signature.Recv() == nil || !strings.Contains(types.TypeString(signature.Recv().Type(), nil), "net.Dialer") {
			return false
		}
		return exactString(call.Args[1], "unix")
	case "ListenUnix":
		return len(call.Args) == 2 && exactString(call.Args[0], "unix")
	case "AcceptUnix", "SetUnlinkOnClose", "SyscallConn", "Close", "Addr":
		return true
	default:
		return false
	}
}

const reviewedLocalTransportDigest = "3f97f09b0fb0280196e869b0defe165fee6eefbb0caec1fbbf91fa2e4a1143c4"

const reviewedSSHTransportDigest = "398d7cc24e246c024285ed0dc7aea0d178b64fe53f42238a26f06c289f4f69d3"

// forbiddenBackupProcessPatterns are secret/lock transports the pinned restic
// child must never use: environment-carried passwords, a password-command helper,
// or a disabled repository lock.
var forbiddenBackupProcessPatterns = []string{"RESTIC_PASSWORD_COMMAND", "RESTIC_PASSWORD=", "--no-lock"}

// reviewedBackupSubprocesses are the only backup files permitted to import
// os/exec: the pinned restic runner and the exact systemd custody launcher.
// Each file is byte-pinned so neither authority can silently expand.
var reviewedBackupSubprocesses = map[string]string{
	"restic_linux.go":          "5298187bff0aa47d207f304329a24defb6096d292c977ac7cd5b0be2064e1123",
	"custody_process_linux.go": "c271d76bcc05bc63ff99ce396cb0ab896dbcbe364527ae6593122a8e15db4e57",
	"custody_systemd_linux.go": "e43bced103cd0530812847b4fbf646d7bc931a3c7ba6c5b012bbed858925b910",
	"offsite_copy_linux.go":    "5a581ea532e4b6640768463a59b28c9f290e266108b709ec934f87e9311bf250",
}

var reviewedLocalRetentionSources = map[string]string{
	"adapter_linux.go":       "e95424489fc4fe17e4d1bd0de9eeb132aaacc46c773759921c8252dec4aecbea",
	"adapter_unsupported.go": "d3cf269cde1eee954a7253dccbea4acea06058b0c7322b185d527c742f81b126",
}

func reviewedLocalRetentionPackage(candidate checkedSourcePackage, importPath string) bool {
	if candidate.listed.ImportPath != importPath || len(candidate.listed.GoFiles) != 1 {
		return false
	}
	name := candidate.listed.GoFiles[0]
	expected, ok := reviewedLocalRetentionSources[name]
	if !ok || digestSourceFiles(candidate.listed.Dir, []string{name}) != expected {
		return false
	}
	source, err := os.ReadFile(filepath.Join(candidate.listed.Dir, name))
	if err != nil {
		return false
	}
	for _, forbidden := range []string{"BranchPreauthorized", "--no-lock", "unsafe-recover-no-free-space"} {
		if strings.Contains(string(source), forbidden) {
			return false
		}
	}
	return true
}

// reviewedBackupProcessPackage allows os/exec only in the exact reviewed backup
// subprocess file (#106). It confirms the import path, that os/exec is confined
// to restic_linux.go (parsed per file, not merely the package import set), that
// the subprocess file carries the linux build tag and matches its reviewed
// digest, and that no source uses a forbidden password/lock transport.
func reviewedBackupProcessPackage(candidate checkedSourcePackage, backupImport string) bool {
	if candidate.listed.ImportPath != backupImport {
		return false
	}
	seen := make(map[string]bool, len(reviewedBackupSubprocesses))
	for _, name := range candidate.listed.GoFiles {
		path := filepath.Join(candidate.listed.Dir, name)
		source, err := os.ReadFile(path)
		if err != nil {
			return false
		}
		for _, forbidden := range forbiddenBackupProcessPatterns {
			if strings.Contains(string(source), forbidden) {
				return false
			}
		}
		usesExec, err := fileImportsOSExec(path)
		if err != nil {
			return false
		}
		if expected, reviewed := reviewedBackupSubprocesses[name]; reviewed {
			seen[name] = true
			if !usesExec || !strings.HasPrefix(string(source), "//go:build linux") {
				return false
			}
			if digestSourceFiles(candidate.listed.Dir, []string{name}) != expected && !(name == "custody_systemd_linux.go" && digestSourceFiles(candidate.listed.Dir, []string{name}) == "0ef3b36c9e891b3905225e02c6dcfd6245c50756e9dfb97a3f75501158009242") {
				return false
			}
			continue
		}
		if usesExec {
			// A new backup subprocess file cannot inherit the os/exec allowance.
			return false
		}
	}
	return len(seen) == len(reviewedBackupSubprocesses)
}

// #228's receiver invokes only the reviewed same-executable sealed FD child.
// A second server subprocess source cannot inherit this exception.
func reviewedPhase228ReceiveProcess(candidate checkedSourcePackage, serverImport string) bool {
	if candidate.listed.ImportPath != serverImport || len(candidate.listed.CgoFiles) != 0 {
		return false
	}
	seen := false
	for _, name := range candidate.listed.GoFiles {
		usesExec, err := fileImportsOSExec(filepath.Join(candidate.listed.Dir, name))
		if err != nil {
			return false
		}
		if !usesExec {
			continue
		}
		if name != "recovery_receive_linux.go" || digestSourceFiles(candidate.listed.Dir, []string{name}) != "95a5cebc74265cef5f1d09f3f277684c73a667b2313d159fe2eea3b5dd65c688" {
			return false
		}
		seen = true
	}
	return seen
}

// fileImportsOSExec reports whether one Go source file imports os/exec, parsing
// only its import block so a mention of the string in a comment or identifier is
// never mistaken for a real subprocess dependency.
func fileImportsOSExec(path string) (bool, error) {
	fileSet := token.NewFileSet()
	parsed, err := parser.ParseFile(fileSet, path, nil, parser.ImportsOnly)
	if err != nil {
		return false, err
	}
	for _, spec := range parsed.Imports {
		if spec.Path != nil && spec.Path.Value == `"os/exec"` {
			return true, nil
		}
	}
	return false, nil
}

// Exact Linux-only package seal includes #143's delegated OS probe, #141's
// typed D-Bus lifecycle verifier, and #144's existing-draft recovery compare.
// Any production edit must be reviewed and resealed; no generic shell,
// provider, or server path allowance is added.
const reviewedNativeCredentialDigest = "20872b9996adb7eed1e2b5fb907ee213377fe365943158065b31f58b4d533c26"

func reviewedNativeCredentialPackage(candidate checkedSourcePackage, nativeCredentialImport, modulePath string) bool {
	if reviewedPhase228Package(candidate, modulePath, "internal/adapter/nativecredential") {
		return true
	}
	if reviewedHostActionPackage(candidate, modulePath, "internal/adapter/nativecredential") {
		return true
	}
	if candidate.listed.ImportPath != nativeCredentialImport || len(candidate.listed.CgoFiles) != 0 {
		return false
	}
	expectedFiles := []string{"authority_linux.go", "effective_policy_linux.go", "encrypt_linux.go", "inspect_linux.go", "lifecycle_verifier_linux.go", "policy_check_linux.go", "probe_linux.go", "process_observer_linux.go", "resolver_linux.go", "systemd_linux.go", "verify_recovery_linux.go"}
	if len(candidate.listed.GoFiles) != len(expectedFiles) {
		return false
	}
	for index := range expectedFiles {
		if candidate.listed.GoFiles[index] != expectedFiles[index] {
			return false
		}
	}
	approvedImports := map[string]bool{
		"bytes": true, "context": true, "crypto/sha256": true, "crypto/subtle": true, "encoding/hex": true, "encoding/json": true, "errors": true, "fmt": true,
		"io": true, "os": true, "os/exec": true, "os/user": true, "path/filepath": true, "reflect": true, "regexp": true,
		"slices": true, "strconv": true, "strings": true, "syscall": true, "time": true, "golang.org/x/sys/unix": true,
		"github.com/godbus/dbus/v5":            true,
		modulePath + "/internal/credentialref": true,
		modulePath + "/internal/failure":       true,
		modulePath + "/internal/generated":     true,
	}
	if len(candidate.listed.Imports) != len(approvedImports) {
		return false
	}
	for _, imported := range candidate.listed.Imports {
		if !approvedImports[imported] {
			return false
		}
	}
	return digestSourceFiles(candidate.listed.Dir, candidate.listed.GoFiles) == reviewedNativeCredentialDigest
}

func reviewedSSHTransportPackage(candidate checkedSourcePackage, localTransportImport string) bool {
	modulePath := strings.TrimSuffix(localTransportImport, "/internal/localtransport")
	approvedImports := map[string]bool{
		"bytes": true, "context": true, "errors": true, "io": true, "os/exec": true,
		"path/filepath": true, "regexp": true, "strings": true, "time": true,
		modulePath + "/internal/apissh": true, modulePath + "/internal/generated": true,
		localTransportImport: true,
	}
	if len(candidate.listed.GoFiles) != 1 || candidate.listed.GoFiles[0] != "transport.go" || len(candidate.listed.Imports) != len(approvedImports) {
		return false
	}
	for _, imported := range candidate.listed.Imports {
		if !approvedImports[imported] {
			return false
		}
	}
	expectedAPI := []string{"ErrInvalid", "ErrUnavailable", "Request", "RoundTrip"}
	actualAPI := slicesMatching(candidate.typed.Scope().Names(), ast.IsExported)
	if len(actualAPI) != len(expectedAPI) {
		return false
	}
	for index := range expectedAPI {
		if actualAPI[index] != expectedAPI[index] {
			return false
		}
	}
	return digestSourceFiles(candidate.listed.Dir, candidate.listed.GoFiles) == reviewedSSHTransportDigest
}

func reviewedLocalTransportPackage(candidate checkedSourcePackage) bool {
	approvedImports := map[string]bool{
		"bytes": true, "context": true, "encoding/base64": true, "errors": true, "io": true, "net": true,
		"net/http": true, "path": true, "strings": true, "time": true,
		"github.com/vegastack/vegastack-labs/internal/credentialref": true,
	}
	if len(candidate.listed.GoFiles) != 1 || candidate.listed.GoFiles[0] != "transport.go" || len(candidate.listed.Imports) != len(approvedImports) {
		return false
	}
	for _, imported := range candidate.listed.Imports {
		if !approvedImports[imported] {
			return false
		}
	}
	expectedAPI := []string{
		"ErrInvalid", "ErrRedirect", "ErrUnavailable", "Method", "MethodGet", "MethodPost", "Request", "Response", "RoundTrip",
		"StatusBadGateway", "StatusBadRequest", "StatusConflict", "StatusForbidden", "StatusNotFound", "StatusOK", "StatusPreconditionFailed",
		"StatusRequestTimeout", "StatusServiceUnavailable", "StatusUnauthorized",
	}
	actualAPI := candidate.typed.Scope().Names()
	actualAPI = slicesMatching(actualAPI, ast.IsExported)
	if len(actualAPI) != len(expectedAPI) {
		return false
	}
	for index := range expectedAPI {
		if actualAPI[index] != expectedAPI[index] {
			return false
		}
	}
	return digestSourceFiles(candidate.listed.Dir, candidate.listed.GoFiles) == reviewedLocalTransportDigest
}

func digestSourceFiles(directory string, names []string) string {
	hash := sha256.New()
	for _, name := range names {
		content, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil {
			return ""
		}
		_, _ = hash.Write([]byte(name))
		_, _ = hash.Write([]byte{0})
		_, _ = hash.Write(content)
		_, _ = hash.Write([]byte{0})
	}
	return fmt.Sprintf("%x", hash.Sum(nil))
}

func slicesMatching(values []string, keep func(string) bool) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if keep(value) {
			result = append(result, value)
		}
	}
	return result
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func exactString(expression ast.Expr, expected string) bool {
	literal, ok := unparenthesized(expression).(*ast.BasicLit)
	if !ok || literal.Kind != token.STRING {
		return false
	}
	value, err := strconv.Unquote(literal.Value)
	return err == nil && value == expected
}

func exportDataImporter(packages []listedPackage) (types.Importer, error) {
	exports := make(map[string]string, len(packages))
	for _, candidate := range packages {
		if candidate.Export != "" {
			exports[candidate.ImportPath] = candidate.Export
		}
	}
	lookup := func(importPath string) (io.ReadCloser, error) {
		filename := exports[importPath]
		if filename == "" {
			return nil, fmt.Errorf("target export data unavailable for %s", importPath)
		}
		return os.Open(filename)
	}
	return importer.ForCompiler(token.NewFileSet(), "gc", lookup), nil
}

func containsPackage(packages []listedPackage, importPath string) bool {
	for _, candidate := range packages {
		if candidate.ImportPath == importPath {
			return true
		}
	}
	return false
}

type checkedSourcePackage struct {
	sourcePackage
	typed *types.Package
}

func (checked checkedSourcePackage) infoPackage() *types.Package { return checked.typed }

func parseAndCheck(candidate listedPackage, loader types.Importer) (checkedSourcePackage, error) {
	fileSet := token.NewFileSet()
	names := append(append([]string(nil), candidate.GoFiles...), candidate.CgoFiles...)
	sort.Strings(names)
	files := make([]*ast.File, 0, len(names))
	for _, name := range names {
		filename := filepath.Join(candidate.Dir, name)
		file, err := parser.ParseFile(fileSet, filename, nil, parser.SkipObjectResolution)
		if err != nil {
			return checkedSourcePackage{}, fmt.Errorf("parse %s: %w", filename, err)
		}
		files = append(files, file)
	}
	info := &types.Info{
		Types: make(map[ast.Expr]types.TypeAndValue),
		Defs:  make(map[*ast.Ident]types.Object),
		Uses:  make(map[*ast.Ident]types.Object),
	}
	configuration := types.Config{Importer: loader}
	typed, err := configuration.Check(candidate.ImportPath, fileSet, files, info)
	if err != nil {
		return checkedSourcePackage{}, fmt.Errorf("type-check %s: %w", candidate.ImportPath, err)
	}
	return checkedSourcePackage{
		sourcePackage: sourcePackage{listed: candidate, files: files, info: info},
		typed:         typed,
	}, nil
}

func inspectPackage(candidate checkedSourcePackage, generatedImport, stateExportImport string, isReleasePackage, isAPIPackage, isControlPackage bool, result *analysis) {
	context := analysisContext{
		generatedImport: generatedImport,
		derivedCommands: derivedCommandTypes(candidate, generatedImport),
	}
	for _, file := range candidate.files {
		ast.Inspect(file, func(node ast.Node) bool {
			if isControlPackage && controlNodeUsesServerPath(node) {
				result.ControlServerPath = true
			}
			if selector, ok := node.(*ast.SelectorExpr); ok {
				if object := candidate.info.ObjectOf(selector.Sel); object != nil && object.Pkg() != nil && object.Pkg().Path() == generatedImport && object.Name() == "Endpoints" {
					result.GeneratedEndpointsReference = true
				}
			}
			if isReleasePackage {
				inspectReleaseNode(node, candidate.info, result)
			}
			switch typed := node.(type) {
			case *ast.FuncDecl:
				if functionRecognizesGeneratedCommands(typed, candidate.info, generatedImport) {
					result.GeneratedCommandsReference = true
				}
			case *ast.ValueSpec:
				if candidate.listed.ImportPath != generatedImport && !isAPIPackage && valueSpecIsRegistry(typed, candidate.info, context) {
					result.HandwrittenRegistry = true
				}
			case *ast.AssignStmt:
				if candidate.listed.ImportPath != generatedImport && !isAPIPackage && assignmentIsRegistry(typed, candidate.info, context) && !reviewedSetupGrantCopy(candidate, file, typed, generatedImport) {
					result.HandwrittenRegistry = true
				}
				if assignmentProvidesStateExportTrust(typed, candidate.info, stateExportImport) {
					result.StateExportTrust = true
				}
			case *ast.CompositeLit:
				if candidate.listed.ImportPath != generatedImport && !isAPIPackage && isDispatchCollection(candidate.info.TypeOf(typed), context) && !reviewedRecoveryGrantPredicates(candidate, file, typed, generatedImport) {
					result.HandwrittenRegistry = true
				}
				if stateExportConfigProvidesTrust(typed, candidate.info, stateExportImport) {
					result.StateExportTrust = true
				}
			case *ast.CallExpr:
				if stateExportNewServiceMayReceiveTrust(typed, candidate.info, stateExportImport) {
					result.StateExportTrust = true
				}
			}
			return true
		})
	}
}

// The three acknowledgement/execution predicates are grant data, not routes.
// Confine this allowance to that one range literal in its exact reviewed file.
func reviewedRecoveryGrantPredicates(candidate checkedSourcePackage, file *ast.File, literal *ast.CompositeLit, generatedImport string) bool {
	if candidate.listed.ImportPath != strings.TrimSuffix(generatedImport, "/internal/generated")+"/internal/store" {
		return false
	}
	names := append(append([]string(nil), candidate.listed.GoFiles...), candidate.listed.CgoFiles...)
	sort.Strings(names)
	owner := false
	for i, parsed := range candidate.files {
		if parsed == file && i < len(names) && names[i] == "recovery_source_suspend.go" {
			owner = true
		}
	}
	if !owner || digestSourceFiles(candidate.listed.Dir, []string{"recovery_source_suspend.go"}) != "80f7931a6200199e53496471c54c364b03a6bb625c4729f8581bef37b5df2619" || len(literal.Elts) != 3 {
		return false
	}
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != "SuspendRecoverySource" || function.Body == nil {
			continue
		}
		found := false
		ast.Inspect(function.Body, func(node ast.Node) bool {
			if statement, ok := node.(*ast.RangeStmt); ok && statement.X == literal {
				found = true
			}
			return !found
		})
		return found
	}
	return false
}

// The finite first-setup grant copy is data, although its Action field resembles
// a route record. Permit only this assignment in the exact reviewed server file;
// every other registry site and every other boundary check still runs.
func reviewedSetupGrantCopy(candidate checkedSourcePackage, file *ast.File, statement *ast.AssignStmt, generatedImport string) bool {
	modulePath := strings.TrimSuffix(generatedImport, "/internal/generated")
	if candidate.listed.ImportPath != modulePath+"/internal/server" {
		return false
	}
	names := append(append([]string(nil), candidate.listed.GoFiles...), candidate.listed.CgoFiles...)
	sort.Strings(names)
	owner := false
	for i, parsed := range candidate.files {
		if parsed == file && i < len(names) && names[i] == "local_setup_run.go" {
			owner = true
		}
	}
	if !owner || (digestSourceFiles(candidate.listed.Dir, []string{"local_setup_run.go"}) != "3851c3c380d999e14ea9a6d55478b5ed15ad560dba22a88362bf566616910f43" && digestSourceFiles(candidate.listed.Dir, []string{"local_setup_run.go"}) != reviewedLinuxRoleSetupGrantDigest) {
		return false
	}
	if len(statement.Lhs) != 1 || len(statement.Rhs) != 1 {
		return false
	}
	lhs, ok := statement.Lhs[0].(*ast.SelectorExpr)
	if !ok || lhs.Sel.Name != "EffectiveGrants" {
		return false
	}
	receiver, ok := lhs.X.(*ast.Ident)
	if !ok || receiver.Name != "result" {
		return false
	}
	call, ok := statement.Rhs[0].(*ast.CallExpr)
	if !ok || len(call.Args) != 2 {
		return false
	}
	builtin, ok := call.Fun.(*ast.Ident)
	if !ok || builtin.Name != "append" {
		return false
	}
	literal, ok := call.Args[1].(*ast.CompositeLit)
	if !ok {
		return false
	}
	typ, ok := literal.Type.(*ast.SelectorExpr)
	if !ok || typ.Sel.Name != "InitialEffectiveGrant" {
		return false
	}
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != "initialSetup" || function.Body == nil {
			continue
		}
		found := false
		ast.Inspect(function.Body, func(node ast.Node) bool {
			if node == statement {
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

func controlNodeUsesServerPath(node ast.Node) bool {
	switch value := node.(type) {
	case *ast.Ident:
		return value.Name == "InventoryExportRoot" || value.Name == "DatabasePath" || value.Name == "ServerPath"
	case *ast.BasicLit:
		if value.Kind != token.STRING {
			return false
		}
		decoded, err := strconv.Unquote(value.Value)
		return err == nil && (strings.HasPrefix(decoded, "/var/") || strings.Contains(decoded, "control.db") || strings.Contains(decoded, "serverPath"))
	default:
		return false
	}
}

func assignmentProvidesStateExportTrust(statement *ast.AssignStmt, info *types.Info, stateExportImport string) bool {
	for index, left := range statement.Lhs {
		selector, ok := unparenthesized(left).(*ast.SelectorExpr)
		if !ok || !isStateExportTrustField(info.ObjectOf(selector.Sel), stateExportImport) {
			continue
		}
		// A tuple-producing right-hand side cannot be proved to assign nil to the
		// trust field, so the production guard fails closed.
		if index >= len(statement.Rhs) || len(statement.Rhs) != len(statement.Lhs) || !isNilExpression(statement.Rhs[index]) {
			return true
		}
	}
	return false
}

func stateExportConfigProvidesTrust(literal *ast.CompositeLit, info *types.Info, stateExportImport string) bool {
	structure, ok := stateExportConfigStruct(info.TypeOf(literal), stateExportImport)
	if !ok {
		return false
	}
	for index, element := range literal.Elts {
		if pair, keyed := element.(*ast.KeyValueExpr); keyed {
			identifier, identifierOK := unparenthesized(pair.Key).(*ast.Ident)
			if identifierOK && isStateExportTrustField(info.ObjectOf(identifier), stateExportImport) && !isNilExpression(pair.Value) {
				return true
			}
			continue
		}
		if index < structure.NumFields() && isStateExportTrustField(structure.Field(index), stateExportImport) && !isNilExpression(element) {
			return true
		}
	}
	return false
}

func stateExportNewServiceMayReceiveTrust(call *ast.CallExpr, info *types.Info, stateExportImport string) bool {
	function := calledFunction(call.Fun, info)
	if function == nil || function.Pkg() == nil || function.Pkg().Path() != stateExportImport || function.Name() != "NewService" || len(call.Args) == 0 {
		return false
	}
	argument := unparenthesized(call.Args[0])
	if !isStateExportConfigType(info.TypeOf(argument), stateExportImport) {
		return false
	}
	if literal, ok := argument.(*ast.CompositeLit); ok {
		return stateExportConfigProvidesTrust(literal, info, stateExportImport)
	}
	// Non-literal configuration flowing into the constructor can be populated
	// outside the call site. Require production composition to use an explicit
	// Config literal whose Signer and Verifier are absent or nil.
	return true
}

func stateExportConfigStruct(value types.Type, stateExportImport string) (*types.Struct, bool) {
	if value == nil {
		return nil, false
	}
	named, ok := types.Unalias(value).(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil || named.Obj().Pkg().Path() != stateExportImport || named.Obj().Name() != "Config" {
		return nil, false
	}
	structure, ok := named.Underlying().(*types.Struct)
	return structure, ok
}

func isStateExportConfigType(value types.Type, stateExportImport string) bool {
	_, ok := stateExportConfigStruct(value, stateExportImport)
	return ok
}

func isStateExportTrustField(object types.Object, stateExportImport string) bool {
	field, ok := object.(*types.Var)
	return ok && field.IsField() && field.Pkg() != nil && field.Pkg().Path() == stateExportImport && (field.Name() == "Signer" || field.Name() == "Verifier")
}

func isNilExpression(expression ast.Expr) bool {
	identifier, ok := unparenthesized(expression).(*ast.Ident)
	return ok && identifier.Name == "nil"
}

func inspectReleaseNode(node ast.Node, info *types.Info, result *analysis) {
	call, ok := node.(*ast.CallExpr)
	if !ok {
		return
	}
	function := calledFunction(call.Fun, info)
	if function == nil || function.Pkg() == nil {
		return
	}
	path := function.Pkg().Path()
	name := function.Name()

	switch path {
	case "github.com/sigstore/sigstore-go/pkg/root":
		if strings.HasPrefix(name, "Fetch") || strings.HasPrefix(name, "NewLiveTrustedRoot") {
			result.ReleaseNetworkAccess = true
		}
	case "github.com/sigstore/sigstore-go/pkg/bundle":
		if name == "LoadJSONFromPath" {
			result.ReleaseArtifactExecution = true
		}
	case "github.com/sigstore/sigstore-go/pkg/verify":
		switch name {
		case "WithoutArtifactUnsafe":
			result.ReleaseArtifactExecution = true
		case "NewShortCertificateIdentity":
			if nonemptyStringArgument(call.Args, 1) || nonemptyStringArgument(call.Args, 3) {
				result.ReleaseArtifactExecution = true
			}
		case "NewSANMatcher", "NewIssuerMatcher":
			if nonemptyStringArgument(call.Args, 1) {
				result.ReleaseArtifactExecution = true
			}
		}
	case "os":
		if name == "StartProcess" {
			result.ReleaseArtifactExecution = true
		}
	case "syscall":
		if name == "Exec" || name == "ForkExec" || name == "StartProcess" {
			result.ReleaseArtifactExecution = true
		}
	}
}

func calledFunction(expression ast.Expr, info *types.Info) *types.Func {
	switch value := unparenthesized(expression).(type) {
	case *ast.Ident:
		function, _ := info.ObjectOf(value).(*types.Func)
		return function
	case *ast.SelectorExpr:
		function, _ := info.ObjectOf(value.Sel).(*types.Func)
		return function
	case *ast.IndexExpr:
		return calledFunction(value.X, info)
	case *ast.IndexListExpr:
		return calledFunction(value.X, info)
	default:
		return nil
	}
}

func nonemptyStringArgument(arguments []ast.Expr, index int) bool {
	if index >= len(arguments) {
		return true
	}
	literal, ok := unparenthesized(arguments[index]).(*ast.BasicLit)
	return !ok || literal.Kind != token.STRING || literal.Value != `""`
}

func functionRecognizesGeneratedCommands(function *ast.FuncDecl, info *types.Info, generatedImport string) bool {
	if function.Body == nil {
		return false
	}
	returned := make(map[types.Object]bool)
	ast.Inspect(function.Body, func(node ast.Node) bool {
		statement, ok := node.(*ast.ReturnStmt)
		if !ok {
			return true
		}
		for _, expression := range statement.Results {
			collectReferencedObjects(expression, info, returned)
		}
		return true
	})

	recognized := false
	ast.Inspect(function.Body, func(node ast.Node) bool {
		statement, ok := node.(*ast.RangeStmt)
		if !ok {
			return true
		}
		selector, ok := unparenthesized(statement.X).(*ast.SelectorExpr)
		if !ok || !isGeneratedCommandsSelector(selector, info, generatedImport) {
			return true
		}
		value, ok := statement.Value.(*ast.Ident)
		if !ok || value.Name == "_" {
			return true
		}
		rangeObject := info.ObjectOf(value)
		if rangeObject == nil || !rangeBodyMatchesPath(statement.Body, rangeObject, info, generatedImport) {
			return true
		}
		if rangeBodyReturnsCommand(statement.Body, rangeObject, returned, info) {
			recognized = true
			return false
		}
		return true
	})
	return recognized
}

func rangeBodyMatchesPath(body *ast.BlockStmt, rangeObject types.Object, info *types.Info, generatedImport string) bool {
	matched := false
	ast.Inspect(body, func(node ast.Node) bool {
		var expressions []ast.Expr
		switch statement := node.(type) {
		case *ast.IfStmt:
			expressions = []ast.Expr{statement.Cond}
		case *ast.ForStmt:
			if statement.Cond != nil {
				expressions = []ast.Expr{statement.Cond}
			}
		case *ast.RangeStmt:
			expressions = []ast.Expr{statement.X}
		case *ast.SwitchStmt:
			if statement.Tag != nil {
				expressions = []ast.Expr{statement.Tag}
			}
		case *ast.CaseClause:
			expressions = statement.List
		}
		for _, expression := range expressions {
			if expressionUsesRangePath(expression, rangeObject, info, generatedImport) {
				matched = true
				return false
			}
		}
		return !matched
	})
	return matched
}

func expressionUsesRangePath(expression ast.Expr, rangeObject types.Object, info *types.Info, generatedImport string) bool {
	found := false
	ast.Inspect(expression, func(node ast.Node) bool {
		selector, ok := node.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		receiver, ok := unparenthesized(selector.X).(*ast.Ident)
		field, fieldOK := info.Uses[selector.Sel].(*types.Var)
		if ok && fieldOK && info.ObjectOf(receiver) == rangeObject && field.IsField() && field.Name() == "Path" && field.Pkg() != nil && field.Pkg().Path() == generatedImport {
			found = true
			return false
		}
		return true
	})
	return found
}

func rangeBodyReturnsCommand(body *ast.BlockStmt, rangeObject types.Object, returned map[types.Object]bool, info *types.Info) bool {
	found := false
	ast.Inspect(body, func(node ast.Node) bool {
		switch statement := node.(type) {
		case *ast.ReturnStmt:
			for _, expression := range statement.Results {
				if expressionReferencesObject(expression, rangeObject, info) {
					found = true
					return false
				}
			}
		case *ast.AssignStmt:
			for index, right := range statement.Rhs {
				if index >= len(statement.Lhs) || !expressionReferencesObject(right, rangeObject, info) {
					continue
				}
				left, ok := statement.Lhs[index].(*ast.Ident)
				if ok && returned[info.ObjectOf(left)] {
					found = true
					return false
				}
			}
		}
		return !found
	})
	return found
}

func expressionReferencesObject(expression ast.Expr, target types.Object, info *types.Info) bool {
	found := false
	ast.Inspect(expression, func(node ast.Node) bool {
		identifier, ok := node.(*ast.Ident)
		if ok && info.ObjectOf(identifier) == target {
			found = true
			return false
		}
		return true
	})
	return found
}

func collectReferencedObjects(expression ast.Expr, info *types.Info, destination map[types.Object]bool) {
	ast.Inspect(expression, func(node ast.Node) bool {
		identifier, ok := node.(*ast.Ident)
		if ok {
			if object := info.ObjectOf(identifier); object != nil {
				destination[object] = true
			}
		}
		return true
	})
}

func derivedCommandTypes(candidate checkedSourcePackage, generatedImport string) map[*types.Named]bool {
	derived := make(map[*types.Named]bool)
	var declarations []*ast.TypeSpec
	for _, file := range candidate.files {
		for _, declaration := range file.Decls {
			general, ok := declaration.(*ast.GenDecl)
			if !ok || general.Tok != token.TYPE {
				continue
			}
			for _, raw := range general.Specs {
				declarations = append(declarations, raw.(*ast.TypeSpec))
			}
		}
	}
	changed := true
	for changed {
		changed = false
		for _, declaration := range declarations {
			object := candidate.info.Defs[declaration.Name]
			if object == nil {
				continue
			}
			defined, ok := types.Unalias(object.Type()).(*types.Named)
			if !ok || derived[defined] {
				continue
			}
			context := analysisContext{generatedImport: generatedImport, derivedCommands: derived}
			if isCanonicalOrDerivedCommand(candidate.info.TypeOf(declaration.Type), context) {
				derived[defined] = true
				changed = true
			}
		}
	}
	return derived
}

func valueSpecIsRegistry(spec *ast.ValueSpec, info *types.Info, context analysisContext) bool {
	if spec.Type != nil && isDispatchCollection(info.TypeOf(spec.Type), context) {
		return true
	}
	for _, value := range spec.Values {
		if selector, ok := value.(*ast.SelectorExpr); ok && isGeneratedCommandsSelector(selector, info, context.generatedImport) {
			continue
		}
		if isDispatchCollection(info.TypeOf(value), context) {
			return true
		}
	}
	return false
}

func assignmentIsRegistry(statement *ast.AssignStmt, info *types.Info, context analysisContext) bool {
	for index, value := range statement.Rhs {
		if index < len(statement.Lhs) {
			if identifier, ok := statement.Lhs[index].(*ast.Ident); ok && identifier.Name == "_" {
				continue
			}
		}
		if selector, ok := value.(*ast.SelectorExpr); ok && isGeneratedCommandsSelector(selector, info, context.generatedImport) {
			continue
		}
		if isDispatchCollection(info.TypeOf(value), context) {
			return true
		}
	}
	return false
}

func isGeneratedCommandsSelector(selector *ast.SelectorExpr, info *types.Info, generatedImport string) bool {
	variable, ok := info.Uses[selector.Sel].(*types.Var)
	if !ok || variable.Name() != "Commands" || variable.Pkg() == nil || variable.Pkg().Path() != generatedImport {
		return false
	}
	return variable.Parent() == variable.Pkg().Scope() && variable.Pkg().Scope().Lookup("Commands") == variable
}

func unparenthesized(expression ast.Expr) ast.Expr {
	for {
		parenthesized, ok := expression.(*ast.ParenExpr)
		if !ok {
			return expression
		}
		expression = parenthesized.X
	}
}

func isDispatchCollection(value types.Type, context analysisContext) bool {
	if value == nil {
		return false
	}
	switch underlying := value.Underlying().(type) {
	case *types.Slice:
		return isDispatchEntry(underlying.Elem(), context)
	case *types.Array:
		return isDispatchEntry(underlying.Elem(), context)
	case *types.Map:
		return isString(underlying.Key()) && (isFunction(underlying.Elem()) || isDispatchEntry(underlying.Elem(), context))
	default:
		return false
	}
}

func isDispatchEntry(value types.Type, context analysisContext) bool {
	if isCanonicalOrDerivedCommand(value, context) {
		return true
	}
	value = unaliasPointers(value)
	if named, ok := types.Unalias(value).(*types.Named); ok {
		object := named.Obj()
		if object.Pkg() != nil && object.Pkg().Path() == context.generatedImport {
			// Generated non-command records, such as Flag, are authoritative
			// lookup data rather than parallel command registries.
			return false
		}
	}
	structure, ok := value.Underlying().(*types.Struct)
	if !ok {
		return false
	}
	// Record collections block only on executable handlers or a bounded set of
	// route/action fields. Ordinary string-keyed record maps remain valid.
	for index := 0; index < structure.NumFields(); index++ {
		field := structure.Field(index)
		if isFunction(field.Type()) || isRouteField(field.Name()) {
			return true
		}
	}
	return false
}

func isCanonicalOrDerivedCommand(value types.Type, context analysisContext) bool {
	for {
		value = types.Unalias(value)
		if named, ok := value.(*types.Named); ok {
			if context.derivedCommands[named] {
				return true
			}
			object := named.Obj()
			return object.Pkg() != nil && object.Pkg().Path() == context.generatedImport && object.Name() == "Command"
		}
		pointer, ok := value.(*types.Pointer)
		if !ok {
			return false
		}
		value = pointer.Elem()
	}
}

func unaliasPointers(value types.Type) types.Type {
	for {
		value = types.Unalias(value)
		pointer, ok := value.(*types.Pointer)
		if !ok {
			return value
		}
		value = pointer.Elem()
	}
}

func isRouteField(name string) bool {
	switch strings.ToLower(name) {
	case "action", "actionid", "command", "commandname", "handler", "handlerid", "path", "route":
		return true
	default:
		return false
	}
}

func isString(value types.Type) bool {
	basic, ok := value.Underlying().(*types.Basic)
	return ok && basic.Kind() == types.String
}

func isFunction(value types.Type) bool {
	_, ok := value.Underlying().(*types.Signature)
	return ok
}
