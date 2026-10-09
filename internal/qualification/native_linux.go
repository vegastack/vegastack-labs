//go:build linux

package qualification

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// RunNative performs only prepared fixed scenario steps. Missing producer steps
// remain not-run; a successful CLI invocation is not scenario qualification.
func RunNative(ctx context.Context, value generated.QualificationScope) (generated.NativeReport, error) {
	start := time.Now().UTC().Truncate(time.Second)
	report := generated.NativeReport{Schema: generated.SchemaIDNativeReport, SchemaVersion: "1.0.0", RunID: value.RunID, ScopeDigest: hostaction.Digest(value), SourceCommit: value.SourceCommit, ExecutableDigest: value.ExecutableDigest, ProfileLockDigest: value.ProfileLockDigest, Scenarios: []generated.ScenarioResult{}, PendingRequirements: []string{}, StartedAt: start.Format(time.RFC3339), FinishedAt: start.Format(time.RFC3339)}
	scope, err := validateScope(value)
	if err != nil {
		return report, err
	}
	expires, _ := time.Parse(time.RFC3339, value.ExpiresAt)
	if !scopeCurrent(scope, time.Now().UTC()) {
		return report, ErrUnavailable
	}
	ctx, cancel := context.WithDeadline(ctx, expires)
	defer cancel()
	if err = validateOuterConfinement(scope); err != nil {
		return report, err
	}
	driver, err := newOwnedGuestLifecycle(ctx, scope)
	if err != nil {
		return report, err
	}
	executable, err := fileDigest("/proc/self/exe", 256*1024*1024)
	if err != nil || executable != value.ExecutableDigest {
		return report, ErrUnavailable
	}
	for id := range scope.guests {
		boot, e := driver.consoleBootID(ctx, id)
		if e != nil {
			return report, e
		}
		driver.bootIDs[id] = boot
		driver.bootAt[id] = time.Now()
	}
	observerErrors := make(chan error, 1)
	go func() { observerErrors <- driver.serveObserver(ctx) }()
	next := map[string]int64{}
	for _, scenario := range scenarioCatalog {
		next[scenario] = 1
		report.Scenarios = append(report.Scenarios, generated.ScenarioResult{Schema: generated.SchemaIDScenarioResult, SchemaVersion: "1.0.0", ScenarioID: scenario, Status: "not-run", ProfileLockDigest: value.ProfileLockDigest, ExecutableDigest: value.ExecutableDigest, StartedAt: start.Format(time.RFC3339), FinishedAt: start.Format(time.RFC3339), PositiveObservationDigests: []string{}, NegativeObservationDigests: []string{}, RecoveryResult: "not-required", CleanupResult: "not-required", QualificationClass: "native", ProducerRunIDs: []string{}, ProducerReceiptDigests: []string{}, NativeObservationDigests: []string{}})
		report.PendingRequirements = append(report.PendingRequirements, scenario)
	}
	runErr := error(nil)
	terminal := false
	for !terminal && ctx.Err() == nil && runErr == nil {
		cleanupRaw, e := ownedFile(filepath.Join(value.OutputRoot, "cleanup.json"), uint32(os.Geteuid()), 32768)
		if e == nil {
			var in generated.NativeStepRequest
			if json.Unmarshal(cleanupRaw, &in) != nil || in.Operation != "cleanup-native" || validateStep(scope, in, time.Now().UTC()) != nil {
				runErr = ErrUnavailable
				break
			}
			terminal = true
			break
		} else if !os.IsNotExist(e) {
			runErr = e
			break
		}
		for i, scenario := range scenarioCatalog {
			ordinal := next[scenario]
			if ordinal > 32 {
				continue
			}
			path := filepath.Join(value.OutputRoot, fmt.Sprintf("%s-%d.json", scenario, ordinal))
			raw, e := ownedFile(path, uint32(os.Geteuid()), 32768)
			if os.IsNotExist(e) {
				continue
			}
			if e != nil {
				runErr = e
				break
			}
			var request generated.NativeStepRequest
			if json.Unmarshal(raw, &request) != nil || request.ScenarioID != scenario || request.Ordinal != ordinal || request.Operation == "cleanup-native" || validateStep(scope, request, time.Now().UTC()) != nil {
				runErr = ErrUnavailable
				break
			}
			result := &report.Scenarios[i]
			if _, e = os.Lstat(filepath.Join(value.OutputRoot, fmt.Sprintf("%s-%d.result.json", scenario, ordinal))); !os.IsNotExist(e) {
				runErr = ErrUnavailable
				break
			}
			if e = driver.waitWitnessWindow(ctx, request); e != nil {
				runErr = e
				break
			}
			if request.Operation == "execute" || request.Operation == "collect-native" {
				report.Changed = true
			}
			output, e := driver.executeConsoleStep(ctx, request)
			result.ArtifactDigest = hostaction.Digest(raw)
			result.Status = "uncertain"
			if e != nil {
				result.RecoveryResult = "uncertain"
				runErr = e
				break
			}
			if e = driver.captureWitness(request, output); e != nil {
				runErr = e
				break
			}
			if e = writeNativeStepOutput(value.OutputRoot, request, output); e != nil {
				runErr = e
				break
			}
			report.Changed = report.Changed || output.Changed
			result.ProducerRunIDs = append(result.ProducerRunIDs, output.ProducerRunIDs...)
			result.FinishedAt = time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)
			next[scenario]++
		}
		if runErr != nil {
			break
		}
		select {
		case e := <-observerErrors:
			runErr = e
			if runErr == nil {
				runErr = ErrUnavailable
			}
			observerErrors = nil
		case <-ctx.Done():
			runErr = ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
	cancel()
	report.Changed = true
	cleanupContext, stopCleanup := context.WithTimeout(context.Background(), 30*time.Second)
	cleanupErr := driver.cleanupOwned(cleanupContext)
	stopCleanup()
	for i := range report.Scenarios {
		report.Scenarios[i].CleanupResult = "passed"
		if cleanupErr != nil {
			report.Scenarios[i].CleanupResult = "uncertain"
		}
		report.Scenarios[i].FinishedAt = time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)
	}
	if cleanupErr != nil {
		report.PendingRequirements = append(report.PendingRequirements, "cleanup-unconfirmed")
	}
	if runErr != nil || !terminal {
		report.PendingRequirements = append(report.PendingRequirements, "native-run-interrupted")
	}
	cancel()
	if observerErrors != nil {
		select {
		case e := <-observerErrors:
			if e != nil && e != context.Canceled {
				report.PendingRequirements = append(report.PendingRequirements, "observer-unavailable")
			}
		case <-time.After(time.Second):
			report.PendingRequirements = append(report.PendingRequirements, "observer-close-unconfirmed")
		}
	}
	report.FinishedAt = time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)
	return report, nil
}
func (d *ownedGuestLifecycle) executeConsoleStep(ctx context.Context, in generated.NativeStepRequest) (generated.NativeStepResult, error) {
	var out generated.NativeStepResult
	for id := range d.scope.guests {
		boot, e := d.consoleBootID(ctx, id)
		if e != nil {
			return out, e
		}
		d.mu.Lock()
		d.bootIDs[id] = boot
		d.bootAt[id] = time.Now()
		d.mu.Unlock()
	}
	controller := ""
	for id, g := range d.scope.guests {
		if g.Role == "controller" {
			controller = id
		}
	}
	if in.Operation == "witness" {
		controller = in.GuestID
	}
	if d.checkProcess(controller) != nil {
		return out, ErrUnavailable
	}
	conn, err := ownedSocket(ctx, filepath.Join(d.scope.value.OutputRoot, controller+".serial"), int(d.launches[controller].QEMUPID))
	if err != nil {
		return out, err
	}
	defer conn.Close()
	deadline, _ := time.Parse(time.RFC3339, in.Deadline)
	if v, ok := ctx.Deadline(); ok && v.Before(deadline) {
		deadline = v
	}
	if conn.SetDeadline(deadline) != nil {
		return out, ErrUnavailable
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if d.authenticateConsole(conn) != nil {
		return out, ErrUnavailable
	}
	command := fmt.Sprintf("\x15/usr/local/bin/vsk-labs qualification step --config /etc/vsk-labs/native/client.json --file /run/vsk-labs-native/%s-%d.json --output json\n", in.ScenarioID, in.Ordinal)
	if _, err = io.WriteString(conn, command); err != nil {
		return out, err
	}
	scanner := bufio.NewScanner(io.LimitReader(conn, 272*1024+1))
	scanner.Buffer(make([]byte, 4096), 256*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var envelope generated.RunResult
		if generated.ValidateContractJSON(generated.SchemaIDRunResult, []byte(line), generated.ContractExact) != nil || json.Unmarshal([]byte(line), &envelope) != nil || envelope.Status != generated.RunStatusSucceeded || envelope.Command != generated.CommandNameQualificationStep {
			continue
		}
		if generated.ValidateContractJSON(generated.SchemaIDNativeStepResult, envelope.Data, generated.ContractExact) != nil || json.Unmarshal(envelope.Data, &out) != nil || hostaction.Digest(out.Binding) != hostaction.Digest(in) {
			return out, ErrUnavailable
		}
		return out, nil
	}
	return out, ErrUnavailable
}
