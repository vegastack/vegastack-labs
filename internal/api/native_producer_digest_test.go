package api

import (
	"encoding/json"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
)

func TestNativeProducerLookupOptionalReceiptDigestContract(t *testing.T) {
	digest := hostaction.Digest("fixture-canonical-receipt")
	data := generated.NativeProducerLookupData{
		Schema: generated.SchemaIDNativeProducerLookupData, SchemaVersion: "1.0.0",
		ProducerReference: generated.NativeProducerReference{
			Schema: generated.SchemaIDNativeProducerReference, SchemaVersion: "1.0.0",
			ScenarioID: "volume-effective-mapping", HostID: "subject", PlanID: "plan", PlanDigest: digest,
			RunID: "run", StepID: "step", LeaseID: "lease",
		},
		ReceiptDigest: digest,
	}
	for _, value := range []string{digest, "", "not-a-receipt-digest"} {
		data.ReceiptDigest = value
		raw, err := json.Marshal(data)
		if err != nil {
			t.Fatal(err)
		}
		err = generated.ValidateContractJSON(generated.SchemaIDNativeProducerLookupData, raw, generated.ContractExact)
		if (err == nil) != (value != "not-a-receipt-digest") {
			t.Fatalf("optional digest %q validation: %v", value, err)
		}
	}
}
