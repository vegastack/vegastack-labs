package serverconfig

import (
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

func freezeNotificationReadiness(p *generated.NotificationReadinessPolicy, g *generated.OperationsGithubDestination) (*generated.NotificationReadinessPolicy, error) {
	if p == nil {
		return nil, nil
	}
	raw, e := json.Marshal(p)
	if e != nil || g == nil || generated.ValidateContractJSON(generated.SchemaIDNotificationReadinessPolicy, raw, generated.ContractExact) != nil || p.PrimaryReferenceID == p.SecondaryReferenceID || p.PrimaryReferenceID == g.ReferenceID {
		return nil, errOperationsProfile
	}
	v := *p
	return &v, nil
}
