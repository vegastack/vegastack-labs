package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestApplicationAndHealthcheck(t *testing.T) {
	server := httptest.NewServer(routes())
	defer server.Close()
	if err := checkHealth(context.Background(), server.URL+"/healthz"); err != nil {
		t.Fatal(err)
	}
	response, err := http.Get(server.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatal(response.StatusCode)
	}
}

func TestHealthcheckRejectsFailureRedirectAndCancellation(t *testing.T) {
	for _, status := range []int{http.StatusServiceUnavailable, http.StatusFound} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Location", "/healthy")
				if r.URL.Path == "/healthy" {
					w.WriteHeader(http.StatusOK)
					return
				}
				w.WriteHeader(status)
			}))
			defer server.Close()
			if err := checkHealth(context.Background(), server.URL); err == nil {
				t.Fatal("non-200 health result accepted")
			}
			if calls.Load() != 1 {
				t.Fatal("healthcheck followed a redirect")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if checkHealth(ctx, "http://127.0.0.1:8080/healthz") == nil {
		t.Fatal("cancelled check succeeded")
	}
}
