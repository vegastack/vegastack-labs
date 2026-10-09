package debianaccess

// NativeRollbackObservation is a sanitized internal fixture witness. It carries
// no configuration bytes, authorized keys, arbitrary paths or passed flags.
// Production constructs it only through ObserveNativeRollback.
type NativeRollbackObservation struct {
	RecordDigest        string `json:"recordDigest"`
	RunID               string `json:"runId"`
	HostID              string `json:"hostId"`
	HostIdentityDigest  string `json:"hostIdentityDigest"`
	PlanID              string `json:"planId"`
	InputDigest         string `json:"inputDigest"`
	AuthorizationDigest string `json:"authorizationDigest"`
	BundleDigest        string `json:"bundleDigest"`
	State               string `json:"state"`
	ArmedAt             string `json:"armedAt"`
	Deadline            string `json:"deadline"`
	ObservedAt          string `json:"observedAt"`
	ArmedBootID         string `json:"armedBootId"`
	ReconciledBootID    string `json:"reconciledBootId,omitempty"`
	CurrentBootID       string `json:"currentBootId"`
	BeforeOwnedDigest   string `json:"beforeOwnedDigest"`
	AppliedOwnedDigest  string `json:"appliedOwnedDigest"`
	CurrentOwnedDigest  string `json:"currentOwnedDigest"`
	FileCount           int    `json:"fileCount"`
	FirewallCount       int    `json:"firewallCount"`
}
