package r2retention

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/vegastack/vegastack-labs/internal/store"
)

type Rule struct{ RuleID, Prefix string }
type RuleSet struct{ Rules []Rule }
type Object struct {
	Key, Digest string
	Bytes       int64
}
type RuleClient interface {
	ReadRules(context.Context, string) (RuleSet, error)
	PutRules(context.Context, string, RuleSet) error
}
type ObjectClient interface {
	ListExact(context.Context, string) ([]Object, error)
	DeleteExact(context.Context, string) error
}
type Recorder interface {
	AppendAttempt(context.Context, store.OffsiteRetirementAttempt) error
}
type EffectJournal struct {
	Status                                               string
	PreRuleDigest, PostRuleDigest, ObjectInventoryDigest string
	DeletedKeys                                          []string
	ReclaimedBytes                                       int64
	UncertainReason                                      string
}

// RetireExact performs the one permitted destructive sequence. There is no
// prefix-delete operation and no optimistic-CAS claim: every ambiguous PUT or
// DELETE ends the attempt as uncertain.
func RetireExact(ctx context.Context, intent store.OffsiteRetirementIntent, lease store.OffsiteRetirementLease, rules RuleClient, objects ObjectClient, recorder Recorder) (EffectJournal, error) {
	journal := EffectJournal{Status: "uncertain"}
	var plannedBytes int64
	for _, object := range intent.Objects {
		if object.Bytes < 0 || object.Bytes > intent.MaxMutationBytes-plannedBytes {
			return journal, errors.New("offsite retirement object bound invalid")
		}
		plannedBytes += object.Bytes
	}
	if rules == nil || objects == nil || recorder == nil || intent.IntentID != lease.IntentID || intent.GenerationID != lease.GenerationID || intent.BucketID != lease.BucketID || intent.RecoveryEpoch != lease.RecoveryEpoch || time.Now().After(lease.MaximumExpiresAt) || lease.LockAdminConsumerID == lease.RetentionConsumerID || len(intent.Rules) != 5 || len(intent.Objects) == 0 || intent.MaxWorkObjects != int64(len(intent.Objects)) || plannedBytes != intent.MaxMutationBytes || lease.MaxWorkObjects != intent.MaxWorkObjects || lease.MaxMutationBytes != intent.MaxMutationBytes {
		return journal, errors.New("offsite retirement authority mismatch")
	}
	pre, err := rules.ReadRules(ctx, intent.BucketID)
	if err != nil {
		return journal, err
	}
	journal.PreRuleDigest = DigestRuleSet(pre)
	if journal.PreRuleDigest != intent.RuleSetDigest {
		return journal, errors.New("offsite rule set drift")
	}
	target := map[string]bool{}
	for _, v := range intent.Rules {
		target[v.RuleID] = true
	}
	remaining := RuleSet{Rules: make([]Rule, 0, len(pre.Rules)-len(target))}
	found := map[string]bool{}
	for _, v := range pre.Rules {
		if target[v.RuleID] {
			found[v.RuleID] = true
			continue
		}
		remaining.Rules = append(remaining.Rules, v)
	}
	if len(found) != 5 || DigestRuleSet(RuleSet{Rules: remaining.Rules}) != intent.SurvivorRuleDigest {
		return journal, errors.New("offsite rule ownership mismatch")
	}
	requestDigest := DigestRuleSet(remaining)
	if err = recorder.AppendAttempt(ctx, attempt(lease, 1, "rule-put", intent.BucketID, requestDigest, "attempted", "")); err != nil {
		return journal, err
	}
	if err = rules.PutRules(ctx, intent.BucketID, remaining); err != nil {
		journal.UncertainReason = "rule-put-response"
		_ = recorder.AppendAttempt(ctx, attempt(lease, 2, "rule-put", intent.BucketID, requestDigest, "uncertain", ""))
		return journal, errors.New("offsite rule put uncertain")
	}
	post, err := rules.ReadRules(ctx, intent.BucketID)
	if err != nil {
		journal.UncertainReason = "rule-post-read"
		return journal, errors.New("offsite rule post-read uncertain")
	}
	journal.PostRuleDigest = DigestRuleSet(post)
	if journal.PostRuleDigest != intent.SurvivorRuleDigest {
		journal.UncertainReason = "rule-race"
		_ = recorder.AppendAttempt(ctx, attempt(lease, 2, "rule-put", intent.BucketID, requestDigest, "uncertain", journal.PostRuleDigest))
		return journal, errors.New("offsite rule race detected")
	}
	for _, v := range post.Rules {
		if target[v.RuleID] {
			journal.UncertainReason = "target-rule-remains"
			return journal, errors.New("target rule remains")
		}
	}
	if err = recorder.AppendAttempt(ctx, attempt(lease, 2, "rule-put", intent.BucketID, requestDigest, "observed", journal.PostRuleDigest)); err != nil {
		return journal, err
	}
	observed, err := objects.ListExact(ctx, intent.GenerationID)
	if err != nil {
		return journal, err
	}
	journal.ObjectInventoryDigest = DigestObjects(observed)
	expected := make([]Object, len(intent.Objects))
	for i, v := range intent.Objects {
		expected[i] = Object{v.Key, v.Digest, v.Bytes}
	}
	if journal.ObjectInventoryDigest != DigestObjects(expected) {
		return journal, errors.New("offsite object inventory drift")
	}
	var sequence int64 = 2
	for _, v := range canonicalObjects(expected) {
		sequence++
		req := digestParts("delete", v.Key, v.Digest, fmt.Sprint(v.Bytes))
		if err = recorder.AppendAttempt(ctx, attempt(lease, sequence, "object-delete", v.Key, req, "attempted", "")); err != nil {
			return journal, err
		}
		if err = objects.DeleteExact(ctx, v.Key); err != nil {
			journal.UncertainReason = "object-delete-response"
			sequence++
			_ = recorder.AppendAttempt(ctx, attempt(lease, sequence, "object-delete", v.Key, req, "uncertain", ""))
			return journal, errors.New("offsite object delete uncertain")
		}
		journal.DeletedKeys = append(journal.DeletedKeys, v.Key)
		journal.ReclaimedBytes += v.Bytes
		sequence++
		if err = recorder.AppendAttempt(ctx, attempt(lease, sequence, "object-delete", v.Key, req, "observed", v.Digest)); err != nil {
			return journal, err
		}
	}
	left, err := objects.ListExact(ctx, intent.GenerationID)
	if err != nil || len(left) != 0 {
		journal.UncertainReason = "object-post-read"
		return journal, errors.New("offsite target objects remain")
	}
	journal.Status = "effects-observed"
	return journal, nil
}

func attempt(l store.OffsiteRetirementLease, sequence int64, kind, target, request, status, response string) store.OffsiteRetirementAttempt {
	return store.OffsiteRetirementAttempt{AttemptID: fmt.Sprintf("%s-%06d", l.LeaseID, sequence), LeaseID: l.LeaseID, Sequence: sequence, Kind: kind, Target: target, RequestDigest: request, Status: status, ResponseDigest: response}
}
func DigestRuleSet(set RuleSet) string {
	rules := append([]Rule(nil), set.Rules...)
	slices.SortFunc(rules, func(a, b Rule) int {
		if a.RuleID < b.RuleID {
			return -1
		}
		if a.RuleID > b.RuleID {
			return 1
		}
		return 0
	})
	body, _ := json.Marshal(rules)
	return digestParts("rules", string(body))
}
func DigestObjects(values []Object) string {
	body, _ := json.Marshal(canonicalObjects(values))
	return digestParts("objects", string(body))
}
func canonicalObjects(values []Object) []Object {
	out := append([]Object(nil), values...)
	slices.SortFunc(out, func(a, b Object) int {
		if a.Key < b.Key {
			return -1
		}
		if a.Key > b.Key {
			return 1
		}
		return 0
	})
	return out
}
func digestParts(values ...string) string {
	h := sha256.New()
	for _, v := range values {
		_, _ = h.Write([]byte(v))
		_, _ = h.Write([]byte{0})
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}
