package r2

import "testing"

func TestQualificationDigestBindsBudgetsObserverAndCutoffEvidence(t *testing.T) {
	base := Qualification{AccountID: "account-a", Bucket: "bucket-a", Prefix: "critical", ObserverReferenceID: "observer-a", RuleDigest: "sha256:rules",
		AvailableBytes: 100, AvailablePUTs: 10, AvailableLISTs: 2, RuleCount: 5, RetainedGenerations: 2,
		PutCutoffCheckID: "r2-expired-put-denied", PutCutoffDigest: "sha256:put", MultipartCutoffCheckID: "r2-expired-multipart-completion-denied", MultipartCutoffDigest: "sha256:multipart"}
	want := DigestQualification(base)
	if want == "" {
		t.Fatal("qualification digest unavailable")
	}
	changed := base
	changed.AvailableBytes++
	if DigestQualification(changed) == want {
		t.Fatal("budget change did not change qualification digest")
	}
	changed = base
	changed.ObserverReferenceID = "observer-b"
	if DigestQualification(changed) == want {
		t.Fatal("observer change did not change qualification digest")
	}
	changed = base
	changed.MultipartCutoffDigest = "sha256:other"
	if DigestQualification(changed) == want {
		t.Fatal("cutoff evidence change did not change qualification digest")
	}
}
