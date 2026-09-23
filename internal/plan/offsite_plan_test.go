package plan

import (
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

func TestOffsitePlanRequiresSingleExactHumanCentralShape(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	declaration := generated.DeclarationRevision{DeclarationType: "backup.offsite", Extensions: []generated.ContractExtension{{Name: "x-credential-bindings", ValueDigest: digest}, {Name: "x-offsite-generation", ValueDigest: digest}}}
	operation := generated.PlanOperation{OperationType: "backup.offsite.copy", AdapterID: "labs.r2-offsite", ArtifactDigest: digest}
	if !sealedSingleOffsiteCopy(declaration, []generated.PlanOperation{operation}) {
		t.Fatal("exact offsite plan rejected")
	}
	operation.Idempotent = true
	if sealedSingleOffsiteCopy(declaration, []generated.PlanOperation{operation}) {
		t.Fatal("idempotent offsite copy admitted")
	}
}
