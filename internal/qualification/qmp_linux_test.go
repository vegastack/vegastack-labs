//go:build linux

package qualification

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestQMPFixedCommandChecksPeerAndReply(t *testing.T) {
	for _, wrong := range []bool{false, true} {
		t.Run(map[bool]string{false: "matched", true: "wrong-reply"}[wrong], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "guest.qmp")
			listener, err := net.Listen("unix", path)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			if err = os.Chmod(path, 0600); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				c, e := listener.Accept()
				if e != nil {
					done <- e
					return
				}
				defer c.Close()
				enc := json.NewEncoder(c)
				dec := json.NewDecoder(bufio.NewReader(c))
				e = enc.Encode(map[string]any{"QMP": map[string]any{"version": "fixture"}})
				if e != nil {
					done <- e
					return
				}
				for _, expected := range []string{"qmp_capabilities", "query-status"} {
					var request struct {
						Execute string `json:"execute"`
						ID      string `json:"id"`
					}
					if e = dec.Decode(&request); e != nil {
						done <- e
						return
					}
					if request.Execute != expected {
						done <- ErrUnavailable
						return
					}
					id := request.ID
					if wrong && expected == "query-status" {
						id = "other"
					}
					reply := map[string]any{}
					if expected == "query-status" {
						reply = map[string]any{"running": true, "status": "running"}
					}
					if e = enc.Encode(map[string]any{"return": reply, "id": id}); e != nil {
						done <- e
						return
					}
				}
				done <- nil
			}()
			status, err := ownedQMP(context.Background(), path, os.Getpid(), qmpStatus)
			if wrong {
				if err == nil {
					t.Fatal("unbound response accepted")
				}
			} else if err != nil || status != "running" {
				t.Fatalf("status=%s err=%v", status, err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestQMPDeniesOtherPIDBeforeProtocol(t *testing.T) {
	path := filepath.Join(t.TempDir(), "guest.qmp")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err = os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = ownedQMP(context.Background(), path, os.Getpid()+1, qmpStatus); err == nil {
		t.Fatal("different process peer accepted")
	}
}
