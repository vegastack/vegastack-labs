package qualification

import (
	"testing"
	"time"
)

func TestFail2banStatusRejectsAmbiguousOrUnboundedIPLists(t *testing.T) {
	raw := []byte("Status for the jail: sshd\n|- Filter\n|  `- Total failed: 5\n`- Actions\n   |- Total banned: 1\n   `- Banned IP list: 192.0.2.10\n")
	got, err := parseFail2banStatus(raw)
	if err != nil || got.FailedTotal != 5 || len(got.Banned) != 1 {
		t.Fatalf("%+v %v", got, err)
	}
	if _, err = parseFail2banStatus(append(raw, []byte("Total failed: 0\n")...)); err == nil {
		t.Fatal("duplicate counter accepted")
	}
	if _, err = parseFail2banStatus([]byte("Total failed: 5\nTotal banned: 1\nBanned IP list: hostname\n")); err == nil {
		t.Fatal("non-numeric ban target accepted")
	}
}
func TestFail2banWitnessRejectsShortenedTimerAndLostAdmin(t *testing.T) {
	start := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	state := func(failed, banned int64, ips []string, at time.Time) NativeFail2banState {
		return NativeFail2banState{FailedTotal: failed, BannedTotal: banned, Banned: ips, MaxRetry: 5, FindTimeSeconds: 600, BanTimeSeconds: 600, ObservedAt: at.Format(time.RFC3339Nano)}
	}
	admin := func(at time.Time) NativeSSHObservation {
		return NativeSSHObservation{SourceAddress: "192.0.2.11", NamespaceDigest: "ns", RouteDigest: "route", Outcomes: []string{"allowed"}, HostKeyVerified: true, ObservedAt: at.Format(time.RFC3339Nano)}
	}
	w := NativeFail2banWitness{Before: state(0, 0, []string{}, start), Banned: state(5, 1, []string{"192.0.2.10"}, start.Add(time.Second)), After: state(5, 1, []string{}, start.Add(602*time.Second)), Failures: NativeSSHObservation{SourceAddress: "192.0.2.10", Outcomes: []string{"denied", "denied", "denied", "denied", "denied"}, HostKeyVerified: true, ObservedAt: start.Add(time.Second).Format(time.RFC3339Nano)}, AdminBefore: admin(start), AdminDuring: admin(start.Add(2 * time.Second)), AdminAfter: admin(start.Add(603 * time.Second)), ElapsedNanoseconds: int64(601 * time.Second)}
	if ValidateFail2banWitness(w) != nil {
		t.Fatal("full software fixture rejected")
	}
	short := w
	short.ElapsedNanoseconds = int64(599 * time.Second)
	if ValidateFail2banWitness(short) == nil {
		t.Fatal("short ban accepted")
	}
	lost := w
	lost.AdminDuring.Outcomes = []string{"denied"}
	if ValidateFail2banWitness(lost) == nil {
		t.Fatal("lost independent admin accepted")
	}
	same := w
	same.Failures.SourceAddress = w.AdminBefore.SourceAddress
	if ValidateFail2banWitness(same) == nil {
		t.Fatal("same source accepted")
	}
}
