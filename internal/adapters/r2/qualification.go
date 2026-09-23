package r2

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// Qualification is the typed, non-secret payload whose digest is carried by
// the current live G-008 evidence. It prevents a protected profile from
// reusing valid evidence with different capacity, identity, or cutoff facts.
type Qualification struct {
	AccountID              string `json:"accountId"`
	Bucket                 string `json:"bucket"`
	Prefix                 string `json:"prefix"`
	ObserverReferenceID    string `json:"observerReferenceId"`
	RuleDigest             string `json:"ruleDigest"`
	AvailableBytes         int64  `json:"availableBytes"`
	AvailablePUTs          int64  `json:"availablePuts"`
	AvailableLISTs         int64  `json:"availableLists"`
	RuleCount              int    `json:"ruleCount"`
	RetainedGenerations    int    `json:"retainedGenerations"`
	PutCutoffCheckID       string `json:"putCutoffCheckId"`
	PutCutoffDigest        string `json:"putCutoffDigest"`
	MultipartCutoffCheckID string `json:"multipartCutoffCheckId"`
	MultipartCutoffDigest  string `json:"multipartCutoffDigest"`
}

func DigestQualification(value Qualification) string {
	raw, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(digest[:])
}
