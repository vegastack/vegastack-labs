//go:build linux

package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/debianaccess"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/hostdiscovery"
	"github.com/vegastack/vegastack-labs/internal/recovery"
	"github.com/vegastack/vegastack-labs/internal/store"
)

func fixtureReplacementFenceRequirements(s store.HostReplacementFenceScope) ([]recovery.BoundaryRequirement, error) {
	if s.State.Status != "frozen" || (s.Request.RestorationClass != "stateless-role" && s.Request.RestorationClass != "control-database") || len(s.Outstanding) != 0 || s.Request.OldHostID == "" || s.Request.NewHostID == "" || debianaccess.ProtectedName(s.Request.NewHostID) || s.AuthorityDigest == "" || len(s.Credentials) > 62 {
		return nil, recovery.ErrWitnessUnavailable
	}
	out := []recovery.BoundaryRequirement{}
	add := func(kind, subject, target, former string, probes ...string) error {
		for _, v := range []string{subject, target, former} {
			if debianaccess.ProtectedName(v) {
				return recovery.ErrWitnessUnavailable
			}
		}
		for _, probe := range probes {
			out = append(out, recovery.BoundaryRequirement{Kind: kind, SubjectID: subject, TargetID: target, FormerIdentityID: former, AdapterID: "https-direct-denial-v1", ProbeID: probe})
		}
		return nil
	}
	if e := add("host-service", s.Request.OldHostID, s.Request.OldHostID, s.Request.OldIdentityDigest, "service-denied", "alternate-process-denied"); e != nil {
		return nil, e
	}

	for _, c := range s.Credentials {
		if c.ReferenceID == "" || c.MaterialVersion == "" || c.ResolverID != "native-systemd" || !((c.ConsumerID == hostaction.AdapterID && c.PurposeID == hostaction.PurposeID) || (c.ConsumerID == hostdiscovery.Consumer && c.PurposeID == hostdiscovery.Purpose)) {
			return nil, recovery.ErrWitnessUnavailable
		}
		identity := hostaction.Digest(struct{ ReferenceID, MaterialVersion string }{c.ReferenceID, c.MaterialVersion})
		if e := add("ssh", c.ReferenceID, c.TargetID, identity, "new-auth-denied", "open-session-denied"); e != nil {
			return nil, e
		}
		if e := add("secret-resolver", c.ReferenceID, c.TargetID, identity, "resolve-denied", "cached-material-denied"); e != nil {
			return nil, e
		}
	}
	if _, e := recovery.HostGenerationRequirementsDigest(out); e != nil {
		return nil, e
	}
	return out, nil
}

// The child is a separately built recovery test binary, never a production
// loader. Two phases ensure durable challenge intent precedes the real probe.
func recordHostReplacementFenceFixture(t *testing.T, ctx context.Context, st *store.Store, repo *store.HostReplacementRepository, x store.HostReplacementExecution, at time.Time) error {
	t.Helper()
	if st == nil {
		return fmt.Errorf("missing authority")
	}
	binary := os.Getenv("VSK_TEST_RECOVERY_FENCE_BINARY")
	if binary == "" {
		// Ordinary source tests build their own test-only verifier. Packaged VM
		// tests supply the binary explicitly, with no Go installation needed.
		binary = filepath.Join(t.TempDir(), "recovery-fence.test")
		buildCtx, stopBuild := context.WithTimeout(ctx, 60*time.Second)
		defer stopBuild()
		build := exec.CommandContext(buildCtx, "go", "test", "-c", "-o", binary, "../recovery")
		if output, err := build.CombinedOutput(); err != nil {
			return fmt.Errorf("build recovery fence fixture: %w: %s", err, output)
		}
	}
	scope, e := repo.CurrentHostReplacementFenceScope(ctx, x)
	if e != nil {
		return e
	}
	required, e := fixtureReplacementFenceRequirements(scope)
	if e != nil {
		return e
	}
	childCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(childCtx, binary, "-test.run=^TestHostGenerationFenceSubprocess$", "-test.timeout=25s")
	cmd.Env = append(os.Environ(), "VSK_TEST_FENCE_CHILD=1")
	stdin, e := cmd.StdinPipe()
	if e != nil {
		return e
	}
	stdout, e := cmd.StdoutPipe()
	if e != nil {
		return e
	}
	var diagnostic bytes.Buffer
	cmd.Stderr = &diagnostic
	if e = cmd.Start(); e != nil {
		return e
	}
	waited := false
	defer func() {
		stdin.Close()
		if !waited {
			cancel()
			_ = cmd.Wait()
		}
	}()
	enc := json.NewEncoder(stdin)
	dec := json.NewDecoder(io.LimitReader(stdout, 262144))
	if e = enc.Encode(struct {
		Required []recovery.BoundaryRequirement
		At       time.Time
	}{required, at}); e != nil {
		return e
	}
	var qualification struct {
		Digest string
		Expiry time.Time
	}
	if e = dec.Decode(&qualification); e != nil {
		return fmt.Errorf("qualification child: %w", e)
	}
	nonce := make([]byte, 32)
	if _, e = rand.Read(nonce); e != nil {
		return e
	}
	requirementsDigest, e := recovery.HostGenerationRequirementsDigest(required)
	if e != nil {
		return e
	}
	deadline := at.Add(time.Minute)
	if qualification.Expiry.Before(deadline) {
		deadline = qualification.Expiry
	}
	b := recovery.HostGenerationFenceBinding{ReplacementID: x.ReplacementID, ControllerInstanceID: scope.ControllerInstanceID, OldHostID: scope.Request.OldHostID, NewHostID: scope.Request.NewHostID, OldIdentityDigest: scope.Request.OldIdentityDigest, NewIdentityDigest: scope.Request.NewIdentityDigest, FrozenAliasesDigest: hostaction.Digest(scope.State.AliasBindings), AuthorityDigest: scope.AuthorityDigest, PlanID: x.PlanID, PlanDigest: x.PlanDigest, RunID: x.RunID, StepID: x.StepID, LeaseID: x.LeaseID, RequirementsDigest: requirementsDigest, QualificationDigest: qualification.Digest, Nonce: hex.EncodeToString(nonce), ReceiptID: "replacement-fence/" + hex.EncodeToString(nonce[:16]), RecoveryEpoch: scope.RecoveryEpoch, PriorGeneration: scope.State.PriorOwnershipGeneration, NextGeneration: scope.State.ProposedOwnershipGeneration, IssuedAt: at, Deadline: deadline}
	raw, e := json.Marshal(b)
	if e != nil {
		return e
	}
	if e = repo.PersistFenceChallenge(ctx, x, raw); e != nil {
		return e
	}
	if e = enc.Encode(b); e != nil {
		return e
	}
	_ = stdin.Close()
	var receipt recovery.HostGenerationFenceReceipt
	if e = dec.Decode(&receipt); e != nil {
		return fmt.Errorf("receipt child: %w", e)
	}
	// Drain the bounded test-runner PASS trailer before waiting on process exit.
	if _, e = io.Copy(io.Discard, io.LimitReader(stdout, 4096)); e != nil {
		return e
	}
	e = cmd.Wait()
	waited = true
	if e != nil {
		return fmt.Errorf("recovery fixture child: %w: %s", e, diagnostic.String())
	}
	raw, e = json.Marshal(receipt)
	if e != nil {
		return e
	}
	return repo.RecordFenceReceipt(ctx, x, raw)
}
