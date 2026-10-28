package serverconfig

import (
	"errors"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"net/url"
	"regexp"
	"strings"
)

var errOperationsProfile = errors.New("invalid operations profile")

func FreezeOperations(b []generated.OperationsBeszelBinding, g *generated.OperationsGithubDestination) ([]generated.OperationsBeszelBinding, *generated.OperationsGithubDestination, error) {
	invalid := func() ([]generated.OperationsBeszelBinding, *generated.OperationsGithubDestination, error) {
		return nil, nil, errOperationsProfile
	}
	validURL := func(s string) bool {
		u, e := url.Parse(s)
		return e == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.Path == "" && u.RawQuery == "" && u.Fragment == "" && u.Opaque == "" && u.RawPath == ""
	}
	validIDs := func(ids ...string) bool {
		for _, id := range ids {
			if _, e := credentialref.ParseID(id); e != nil {
				return false
			}
		}
		return true
	}
	seen := map[string]bool{}
	if len(b) > 64 {
		return invalid()
	}
	for _, v := range b {
		if v.Schema != generated.SchemaIDOperationsBeszelBinding || v.SchemaVersion != "1.0.0" || !validURL(v.Endpoint) || !regexp.MustCompile(`^[a-z0-9]{15}$`).MatchString(v.RecordID) || !validIDs(v.TargetID, v.ReferenceID, v.MaterialVersion) || v.TargetID == "vsk-node-04" || v.TargetID == "vsk-node-05" || v.StaleAfterSeconds < 1 || v.StaleAfterSeconds > 3600 || seen[v.TargetID] || seen[v.Endpoint+"/"+v.RecordID] {
			return invalid()
		}
		seen[v.TargetID] = true
		seen[v.Endpoint+"/"+v.RecordID] = true
	}
	var out *generated.OperationsGithubDestination
	if g != nil {
		if g.Schema != generated.SchemaIDOperationsGithubDestination || g.SchemaVersion != "1.0.0" || !validURL(g.Endpoint) || !regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$`).MatchString(g.Repository) || strings.Contains(g.Repository, "..") || g.RepositoryID <= 0 || !validIDs(g.TargetID, g.ReferenceID, g.MaterialVersion) {
			return invalid()
		}
		v := *g
		out = &v
	}
	return append([]generated.OperationsBeszelBinding(nil), b...), out, nil
}
