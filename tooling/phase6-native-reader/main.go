// phase6-native-reader is a development read-only client of the existing local
// API. It is never installed as a platform executable or host service.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localapi"
	"github.com/vegastack/vegastack-labs/internal/localtransport"
	"github.com/vegastack/vegastack-labs/internal/result"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
)

type request struct {
	RunIDs []string `json:"runIds"`
}
type trace struct {
	Gates        []generated.RunResult                  `json:"gates"`
	Runs         []generated.RunResult                  `json:"runs"`
	Plans        []generated.Plan                       `json:"plans"`
	Declarations []generated.BrowserDeclarationRevision `json:"declarations"`
}

var token = regexp.MustCompile(`^[a-z][a-z0-9._:-]{0,127}$`)

func read(ctx context.Context, config string, input request) (trace, error) {
	var out trace
	if len(input.RunIDs) > 128 {
		return out, fmt.Errorf("input")
	}
	profile, e := serverconfig.NewLoader(uint32(os.Geteuid())).Load(ctx, config)
	if e != nil {
		return out, e
	}
	// This lane is intentionally local. Report content cannot select a transport,
	// remote endpoint, credential or path. Only the separately supplied protected
	// operator configuration selects the already-running local socket.
	if profile.ConstrainedSSH != nil || profile.SocketPath == "" {
		return out, fmt.Errorf("local-api")
	}
	client := localapi.NewClient(result.NewFactory(result.BuildInfo{ToolVersion: "0.6.0", ReleaseBuildID: "phase6-reader"}, func() (string, error) { b := make([]byte, 16); _, e := rand.Read(b); return hex.EncodeToString(b), e }))
	for _, stage := range []string{"baseline", "role", "recovery"} {
		g, e := client.GetGate(ctx, profile, "native."+stage)
		if e != nil || g.ExitCode != 0 {
			return out, fmt.Errorf("gate")
		}
		out.Gates = append(out.Gates, g.Result)
	}
	seen := map[string]bool{}
	plans := map[string]bool{}
	for _, id := range input.RunIDs {
		if !token.MatchString(id) || seen[id] {
			return out, fmt.Errorf("run")
		}
		seen[id] = true
		r, e := client.InspectRun(ctx, profile, id)
		if e != nil || r.ExitCode != 0 {
			return out, fmt.Errorf("run")
		}
		out.Runs = append(out.Runs, r.Result)
		if plans[r.Data.Run.PlanID] {
			continue
		}
		plans[r.Data.Run.PlanID] = true
		p, e := client.GetPlan(ctx, profile, r.Data.Run.PlanID)
		if e != nil || p.ExitCode != 0 {
			return out, fmt.Errorf("plan")
		}
		out.Plans = append(out.Plans, p.Data)
		if !token.MatchString(p.Data.DeclarationID) || p.Data.Binding.DeclarationRevision < 1 {
			return out, fmt.Errorf("declaration")
		}
		route := fmt.Sprintf("/api/v1/declarations/%s/revisions/%d", p.Data.DeclarationID, p.Data.Binding.DeclarationRevision)
		response, e := localtransport.RoundTrip(ctx, localtransport.Request{SocketPath: profile.SocketPath, Method: localtransport.MethodGet, Path: route, Timeout: 30 * time.Second, ResponseLimit: 65536})
		if e != nil || response.StatusCode != 200 {
			return out, fmt.Errorf("declaration")
		}
		var envelope generated.RunResult
		var d generated.BrowserDeclarationRevision
		if generated.ValidateContractJSON(generated.SchemaIDRunResult, response.Body, generated.ContractExact) != nil || json.Unmarshal(response.Body, &envelope) != nil || envelope.Changed || envelope.Status != "succeeded" || generated.ValidateContractJSON(generated.SchemaIDBrowserDeclarationRevision, envelope.Data, generated.ContractExact) != nil || json.Unmarshal(envelope.Data, &d) != nil || d.DeclarationID != p.Data.DeclarationID || d.Revision != p.Data.Binding.DeclarationRevision {
			return out, fmt.Errorf("declaration")
		}
		out.Declarations = append(out.Declarations, d)
	}
	// Resolve current gates again after every lineage read. A current epoch,
	// profile or qualification change during inspection cannot retain a pass.
	for i, stage := range []string{"baseline", "role", "recovery"} {
		g, e := client.GetGate(ctx, profile, "native."+stage)
		if e != nil || g.ExitCode != 0 {
			return out, fmt.Errorf("gate")
		}
		before := out.Gates[i]
		if before.StateRevision != g.Result.StateRevision || before.RecoveryEpoch != g.Result.RecoveryEpoch || !sameGate(before.Data, g.Result.Data) {
			return out, fmt.Errorf("drift")
		}
		out.Gates[i] = g.Result
	}
	return out, nil
}
func main() {
	if len(os.Args) != 3 || os.Args[1] != "--config" {
		fmt.Fprintln(os.Stderr, "PHASE6_NATIVE_PENDING:arguments")
		os.Exit(2)
	}
	raw, e := io.ReadAll(io.LimitReader(os.Stdin, 65537))
	var input request
	if e != nil || len(raw) > 65536 {
		fmt.Fprintln(os.Stderr, "PHASE6_NATIVE_PENDING:input")
		os.Exit(2)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&input) != nil {
		fmt.Fprintln(os.Stderr, "PHASE6_NATIVE_PENDING:input")
		os.Exit(2)
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	out, e := read(ctx, os.Args[2], input)
	if e != nil {
		fmt.Fprintln(os.Stderr, "PHASE6_NATIVE_PENDING:current-api")
		os.Exit(2)
	}
	if json.NewEncoder(os.Stdout).Encode(out) != nil {
		os.Exit(1)
	}
}

func sameGate(a, b json.RawMessage) bool {
	var x, y generated.GateView
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	x.Evaluation.EvaluatedAt = ""
	y.Evaluation.EvaluatedAt = ""
	x.Evaluation.EvaluationID = ""
	y.Evaluation.EvaluationID = ""
	xb, _ := json.Marshal(x)
	yb, _ := json.Marshal(y)
	return bytes.Equal(xb, yb)
}
