package serverconfig

import (
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"net/url"
	"path/filepath"
	"regexp"
)

func FreezeManualPublicationBindings(in []generated.ManualPublicationBinding) ([]generated.ManualPublicationBinding, error) {
	bad := func() ([]generated.ManualPublicationBinding, error) {
		return nil, failure.New(generated.ErrorCodeInputInvalid, "manual-publication", false)
	}
	if len(in) > 128 {
		return bad()
	}
	out := append([]generated.ManualPublicationBinding(nil), in...)
	ids := map[string]bool{}
	repository := regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$`)
	for _, b := range out {
		raw, _ := json.Marshal(b)
		u, e := url.Parse(b.RegistryOrigin)
		if generated.ValidateContractJSON(generated.SchemaIDManualPublicationBinding, raw, generated.ContractExact) != nil || ids[b.BindingID] || e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Opaque != "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || !repository.MatchString(b.Repository) || len(b.Repository) > 255 || !filepath.IsAbs(b.CandidatePath) || filepath.Clean(b.CandidatePath) != b.CandidatePath || !filepath.IsAbs(b.TrustPolicyPath) || filepath.Clean(b.TrustPolicyPath) != b.TrustPolicyPath {
			return bad()
		}
		ids[b.BindingID] = true
	}
	return out, nil
}
