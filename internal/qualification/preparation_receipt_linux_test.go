//go:build linux

package qualification

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/localapi"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
)

type receiptLookupClient struct {
	localapi.Client
	response localapi.TypedResponse[generated.NativeProducerLookupData]
}

func (c receiptLookupClient) LookupNativeProducerReference(context.Context, serverconfig.Profile, generated.NativeProducerLookupRequest) (localapi.TypedResponse[generated.NativeProducerLookupData], error) {
	return c.response, nil
}

func TestNativePreparationPreservesAPIReceiptDigest(t *testing.T) {
	digest := hostaction.Digest("fixture-canonical-receipt")
	apiJSON := []byte(`{"schema":"vegastack-labs.dev/native-producer-lookup-data","schemaVersion":"1.0.0","producerReference":{"schema":"vegastack-labs.dev/native-producer-reference","schemaVersion":"1.0.0","scenarioId":"volume-effective-mapping","hostId":"subject","planId":"plan","planDigest":"` + digest + `","runId":"run","stepId":"step","leaseId":"lease"},"receiptDigest":"` + digest + `"}`)
	var data generated.NativeProducerLookupData
	if err := generated.ValidateContractJSON(generated.SchemaIDNativeProducerLookupData, apiJSON, generated.ContractExact); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(apiJSON, &data); err != nil {
		t.Fatal(err)
	}
	client := receiptLookupClient{response: localapi.TypedResponse[generated.NativeProducerLookupData]{Data: data}}
	packet := nativeAPIPacket{Kind: "prepare", Preparation: &generated.NativePreparationRequest{Kind: "producer-lookup", ProducerLookup: &generated.NativeProducerLookupRequest{}}}
	reply, err := dispatchNativeAPI(context.Background(), packet, client, serverconfig.Profile{})
	if err != nil || reply.Result.Preparation == nil || reply.Result.Preparation.ReceiptDigest != digest {
		t.Fatalf("native wrapper lost API receipt digest: %+v %v", reply.Result.Preparation, err)
	}
	raw, err := json.Marshal(reply.Result)
	if err != nil {
		t.Fatal(err)
	}
	var privateInput struct {
		Preparation struct {
			ReceiptDigest string `json:"receiptDigest"`
		} `json:"preparation"`
	}
	if err := json.Unmarshal(raw, &privateInput); err != nil || privateInput.Preparation.ReceiptDigest != digest {
		t.Fatal("protected NativeStep result dropped digest", err)
	}
	client.response.ExitCode = 1
	reply, err = dispatchNativeAPI(context.Background(), packet, client, serverconfig.Profile{})
	if err != nil || reply.Result.Preparation == nil || reply.Result.Preparation.ReceiptDigest != "" || reply.Result.Preparation.ProducerReference != nil {
		t.Fatal("failed API response disclosed receipt", err)
	}
}
