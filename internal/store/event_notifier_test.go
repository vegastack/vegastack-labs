package store

import "testing"

func TestEventNotifierCoalescesAndClosesIdempotently(t *testing.T) {
	notifier := newEventNotifier()
	subscription := notifier.subscribe()
	for index := 0; index < EventSignalQueue+20; index++ {
		notifier.signal()
	}
	for index := 0; index < EventSignalQueue; index++ {
		select {
		case <-subscription.C():
		default:
			t.Fatalf("signal %d absent", index)
		}
	}
	select {
	case <-subscription.C():
		t.Fatal("queue exceeded bound")
	default:
	}
	subscription.Close()
	subscription.Close()
	if _, open := <-subscription.C(); open {
		t.Fatal("subscription stayed open")
	}
}
