package r2retention

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/store"
)

type fakeRules struct {
	current    RuleSet
	race, lose bool
}

func (f *fakeRules) ReadRules(context.Context, string) (RuleSet, error) { return f.current, nil }
func (f *fakeRules) PutRules(_ context.Context, _ string, next RuleSet) error {
	f.current = next
	if f.race {
		f.current.Rules = append(f.current.Rules, Rule{"survivor-raced", "survivor/raced/"})
	}
	if f.lose {
		return errors.New("lost response")
	}
	return nil
}

type fakeObjects struct {
	values  []Object
	deletes int
	failAt  int
}

func (f *fakeObjects) ListExact(context.Context, string) ([]Object, error) {
	return append([]Object(nil), f.values...), nil
}
func (f *fakeObjects) DeleteExact(_ context.Context, key string) error {
	f.deletes++
	if f.failAt == f.deletes {
		return errors.New("lost response")
	}
	for i, v := range f.values {
		if v.Key == key {
			f.values = append(f.values[:i], f.values[i+1:]...)
			return nil
		}
	}
	return errors.New("unlisted")
}

type memoryRecorder struct {
	attempts []store.OffsiteRetirementAttempt
}

func (m *memoryRecorder) AppendAttempt(_ context.Context, a store.OffsiteRetirementAttempt) error {
	m.attempts = append(m.attempts, a)
	return nil
}

func TestOffsiteRuleRaceNeverReachesObjectDelete(t *testing.T) {
	pre := RuleSet{Rules: []Rule{{"target-1", "g/config"}, {"target-2", "g/keys/"}, {"target-3", "g/data/"}, {"target-4", "g/index/"}, {"target-5", "g/snapshots/"}, {"survivor-1", "s/config"}}}
	survivor := RuleSet{Rules: []Rule{{"survivor-1", "s/config"}}}
	object := Object{"g/data/a", "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 7}
	intent := store.OffsiteRetirementIntent{IntentID: "intent-a", GenerationID: "generation-a", BucketID: "bucket-a", RuleSetDigest: DigestRuleSet(pre), SurvivorRuleDigest: DigestRuleSet(survivor), RecoveryEpoch: 2, MaxWorkObjects: 1, MaxMutationBytes: 7, Rules: []store.OffsiteRetirementRule{{"target-1", "g/config"}, {"target-2", "g/keys/"}, {"target-3", "g/data/"}, {"target-4", "g/index/"}, {"target-5", "g/snapshots/"}}, Objects: []store.OffsiteRetirementObject{{Key: object.Key, Digest: object.Digest, Bytes: object.Bytes}}}
	lease := store.OffsiteRetirementLease{IntentID: intent.IntentID, GenerationID: intent.GenerationID, BucketID: intent.BucketID, LockAdminConsumerID: "lock-admin", RetentionConsumerID: "retention", RecoveryEpoch: 2, MaxWorkObjects: 1, MaxMutationBytes: 7, MaximumExpiresAt: time.Now().Add(time.Hour), LeaseID: "lease-a"}
	rules := &fakeRules{current: pre, race: true}
	objects := &fakeObjects{values: []Object{object}}
	recorder := &memoryRecorder{}
	journal, err := RetireExact(context.Background(), intent, lease, rules, objects, recorder)
	if err == nil || journal.UncertainReason != "rule-race" || objects.deletes != 0 || len(recorder.attempts) != 2 || recorder.attempts[1].Status != "uncertain" {
		t.Fatalf("race did not fail closed: journal=%+v deletes=%d err=%v", journal, objects.deletes, err)
	}
}

func TestOffsiteDeleteResponseLossStaysUncertain(t *testing.T) {
	pre := RuleSet{Rules: []Rule{{"t1", "g/config"}, {"t2", "g/keys/"}, {"t3", "g/data/"}, {"t4", "g/index/"}, {"t5", "g/snapshots/"}, {"s1", "s/config"}}}
	survivor := RuleSet{Rules: []Rule{{"s1", "s/config"}}}
	object := Object{"g/data/a", "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 7}
	intent := store.OffsiteRetirementIntent{IntentID: "i", GenerationID: "g", BucketID: "b", RuleSetDigest: DigestRuleSet(pre), SurvivorRuleDigest: DigestRuleSet(survivor), RecoveryEpoch: 1, MaxWorkObjects: 1, MaxMutationBytes: 7, Rules: []store.OffsiteRetirementRule{{"t1", "g/config"}, {"t2", "g/keys/"}, {"t3", "g/data/"}, {"t4", "g/index/"}, {"t5", "g/snapshots/"}}, Objects: []store.OffsiteRetirementObject{{Key: object.Key, Digest: object.Digest, Bytes: 7}}}
	lease := store.OffsiteRetirementLease{LeaseID: "l", IntentID: "i", GenerationID: "g", BucketID: "b", LockAdminConsumerID: "a", RetentionConsumerID: "r", RecoveryEpoch: 1, MaxWorkObjects: 1, MaxMutationBytes: 7, MaximumExpiresAt: time.Now().Add(time.Hour)}
	objects := &fakeObjects{values: []Object{object}, failAt: 1}
	recorder := &memoryRecorder{}
	j, err := RetireExact(context.Background(), intent, lease, &fakeRules{current: pre}, objects, recorder)
	if err == nil || j.UncertainReason != "object-delete-response" || recorder.attempts[len(recorder.attempts)-1].Status != "uncertain" {
		t.Fatalf("lost response accepted: %+v %v", j, err)
	}
}
