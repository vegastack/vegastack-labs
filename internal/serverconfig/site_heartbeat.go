package serverconfig

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"strings"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

var heartbeatBucket = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
var heartbeatDigest = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
var heartbeatPolicyVersion = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)

func FreezeSiteHeartbeat(input *generated.OperationsHeartbeatBinding, backup *OffsiteBackup) (*generated.OperationsHeartbeatBinding, error) {
	if input == nil {
		return nil, nil
	}
	invalid := errors.New("invalid site heartbeat profile")
	endpoint, err := url.Parse(input.Endpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.Path != "" || endpoint.Port() != "" || !strings.HasSuffix(endpoint.Hostname(), ".r2.cloudflarestorage.com") || !heartbeatBucket.MatchString(input.Bucket) || input.ObjectKey != "heartbeat.json" || !heartbeatDigest.MatchString(input.SiteDigest) || !heartbeatPolicyVersion.MatchString(input.PolicyVersion) || input.Schema != "vegastack-labs.dev/operations-heartbeat-binding" || input.SchemaVersion != "1.0.0" || input.TargetID == "vsk-node-04" || input.TargetID == "vsk-node-05" {
		return nil, invalid
	}
	for _, id := range []string{input.TargetID, input.ReferenceID, input.MaterialVersion, input.PolicyID} {
		if _, err := credentialref.ParseID(id); err != nil {
			return nil, invalid
		}
	}
	if backup != nil && (input.Bucket == backup.Bucket || input.ReferenceID == backup.ParentReferenceID || input.ReferenceID == backup.ObserverReferenceID || input.ReferenceID == backup.LockAdminReferenceID || input.ReferenceID == backup.RetentionReferenceID) {
		return nil, invalid
	}
	output := *input
	return &output, nil
}

// HeartbeatCapability binds the complete protected destination/ref/policy input
// into an existing human-applied profile capability, never a new approval path.
func HeartbeatCapability(binding generated.OperationsHeartbeatBinding) string {
	raw, _ := json.Marshal(binding)
	digest := sha256.Sum256(raw)
	return "operations.heartbeat." + hex.EncodeToString(digest[:])
}
