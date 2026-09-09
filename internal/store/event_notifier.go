package store

import "sync"

const EventSignalQueue = 64

type EventSubscription interface {
	C() <-chan struct{}
	Close()
}

type eventNotifier struct {
	mu     sync.Mutex
	next   uint64
	closed bool
	subs   map[uint64]chan struct{}
}

type eventSubscription struct {
	n    *eventNotifier
	id   uint64
	c    <-chan struct{}
	once sync.Once
}

func newEventNotifier() *eventNotifier { return &eventNotifier{subs: make(map[uint64]chan struct{})} }

func (notifier *eventNotifier) subscribe() EventSubscription {
	notifier.mu.Lock()
	defer notifier.mu.Unlock()
	channel := make(chan struct{}, EventSignalQueue)
	if notifier.closed {
		close(channel)
		return &eventSubscription{c: channel}
	}
	notifier.next++
	notifier.subs[notifier.next] = channel
	return &eventSubscription{n: notifier, id: notifier.next, c: channel}
}
func (notifier *eventNotifier) signal() {
	notifier.mu.Lock()
	defer notifier.mu.Unlock()
	for _, channel := range notifier.subs {
		select {
		case channel <- struct{}{}:
		default:
		}
	}
}
func (notifier *eventNotifier) close(id uint64) {
	notifier.mu.Lock()
	defer notifier.mu.Unlock()
	if channel, ok := notifier.subs[id]; ok {
		delete(notifier.subs, id)
		close(channel)
	}
}
func (notifier *eventNotifier) closeAll() {
	notifier.mu.Lock()
	defer notifier.mu.Unlock()
	if notifier.closed {
		return
	}
	notifier.closed = true
	for id, channel := range notifier.subs {
		delete(notifier.subs, id)
		close(channel)
	}
}
func (subscription *eventSubscription) C() <-chan struct{} { return subscription.c }
func (subscription *eventSubscription) Close() {
	subscription.once.Do(func() {
		if subscription.n != nil {
			subscription.n.close(subscription.id)
		}
	})
}

func (store *Store) SubscribeEventCommits() EventSubscription { return store.events.subscribe() }
