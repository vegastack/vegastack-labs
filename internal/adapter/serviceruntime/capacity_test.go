package serviceruntime

import (
	"context"
	"golang.org/x/crypto/ssh"
	"strconv"
	"strings"
	"testing"
)

func TestObserveCapacityPinnedMachineAndBoundedOSFacts(t *testing.T) {
	for _, mode := range []string{"healthy", "machine"} {
		t.Run(mode, func(t *testing.T) {
			target, _, value, p := fixture(t, mode)
			target.ApplicationUUID = "application-one"
			calls := 0
			out, e := NewClient().ObserveCapacity(context.Background(), target, value, func(context.Context) error { calls++; return nil })
			if mode == "machine" {
				if e == nil {
					t.Fatal("wrong machine accepted")
				}
				return
			}
			if e != nil || out.CPUQuotaPercent != 300 || out.MemoryBytes != 3865470561 || out.StorageBytes != 9663676416 || calls < 6 {
				t.Fatalf("capacity %+v err %v checks %d", out, e, calls)
			}
			p.mu.Lock()
			defer p.mu.Unlock()
			for _, cmd := range p.commands {
				if strings.Contains(cmd, "container stop") || strings.Contains(cmd, "container start") {
					t.Fatal("capacity observation mutated Docker")
				}
			}
		})
	}
}

func TestObserveCapacityAccountsForUnregisteredContainerLimits(t *testing.T) {
	for _, mode := range []string{"healthy", "resources"} {
		t.Run(mode, func(t *testing.T) {
			target, _, value, _ := fixture(t, mode)
			target.ApplicationUUID = "another-application"
			out, e := NewClient().ObserveCapacity(context.Background(), target, value, func(context.Context) error { return nil })
			if mode == "healthy" {
				if e == nil {
					t.Fatal("unlimited unrelated container became spare CPU")
				}
			} else if e != nil || out.CPUQuotaPercent != 175 {
				t.Fatal("unregistered enforced allocation ignored", out, e)
			}
		})
	}
}

func TestObserveCapacityPinnedAlgorithmWithMultipleServerKeys(t *testing.T) {
	for _, wrongPin := range []bool{false, true} {
		t.Run(strconv.FormatBool(wrongPin), func(t *testing.T) {
			target, _, value, p := fixture(t, "healthy", true)
			target.ApplicationUUID = "application-one"
			if wrongPin {
				other, _ := key(t)
				target.HostKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(other.PublicKey())))
			}
			out, e := NewClient().ObserveCapacity(context.Background(), target, value, func(context.Context) error { return nil })
			if wrongPin {
				if e == nil {
					t.Fatal("different pinned key accepted")
				}
				p.mu.Lock()
				defer p.mu.Unlock()
				if len(p.commands) != 0 {
					t.Fatal("command executed before host key verification")
				}
			} else if e != nil || out.CPUQuotaPercent != 300 {
				t.Fatal("registered Ed25519 key lost to unrelated advertised ECDSA key", out, e)
			}
		})
	}
}
