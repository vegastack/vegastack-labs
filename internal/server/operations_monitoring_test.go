package server

import (
	"context"
	"testing"
)

func TestOperationsMissingPrincipalCannotReadSourcesOrBorrow(t *testing.T) {
	m := &operationsMonitoring{}
	if _, e := m.observe(context.Background()); e == nil {
		t.Fatal("unauthenticated collection allowed")
	}
	if m.deliveryAllowed(context.Background()) {
		t.Fatal("missing destination enabled delivery")
	}
}
