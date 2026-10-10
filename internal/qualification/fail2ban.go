package qualification

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
)

// NativeFail2banInput is loaded only from a fixed protected fixture slot. Its
// network references use the existing prepared #225 source/tuple contracts.
type NativeFail2banInput struct {
	Target      generated.HostDiscoveryTarget `json:"target"`
	Source      generated.AccessProbeSource   `json:"source"`
	Destination generated.AccessProbeTuple    `json:"destination"`
}
type NativeSSHObservation struct {
	SourceHostID              string   `json:"sourceHostId"`
	SourceIdentityDigest      string   `json:"sourceIdentityDigest"`
	DestinationHostID         string   `json:"destinationHostId"`
	DestinationIdentityDigest string   `json:"destinationIdentityDigest"`
	DestinationAddress        string   `json:"destinationAddress"`
	DestinationPort           int64    `json:"destinationPort"`
	User                      string   `json:"user"`
	PublicKeyDigest           string   `json:"publicKeyDigest,omitempty"`
	InputDigest               string   `json:"inputDigest"`
	SourceAddress             string   `json:"sourceAddress"`
	NamespaceDigest           string   `json:"namespaceDigest"`
	RouteDigest               string   `json:"routeDigest"`
	Outcomes                  []string `json:"outcomes"`
	HostKeyVerified           bool     `json:"hostKeyVerified"`
	ObservedAt                string   `json:"observedAt"`
}
type NativeFail2banState struct {
	FailedTotal     int64    `json:"failedTotal"`
	BannedTotal     int64    `json:"bannedTotal"`
	Banned          []string `json:"banned"`
	MaxRetry        int64    `json:"maxRetry"`
	FindTimeSeconds int64    `json:"findTimeSeconds"`
	BanTimeSeconds  int64    `json:"banTimeSeconds"`
	ObservedAt      string   `json:"observedAt"`
}
type NativeFail2banWitness struct {
	Before             NativeFail2banState  `json:"before"`
	Banned             NativeFail2banState  `json:"banned"`
	After              NativeFail2banState  `json:"after"`
	Failures           NativeSSHObservation `json:"failures"`
	AdminBefore        NativeSSHObservation `json:"adminBefore"`
	AdminDuring        NativeSSHObservation `json:"adminDuring"`
	AdminAfter         NativeSSHObservation `json:"adminAfter"`
	ElapsedNanoseconds int64                `json:"elapsedNanoseconds"`
}

func parseFail2banStatus(raw []byte) (NativeFail2banState, error) {
	out := NativeFail2banState{Banned: []string{}}
	seen := map[string]bool{}
	if len(raw) > 16384 {
		return out, ErrUnavailable
	}
	for _, line := range strings.Split(string(raw), "\n") {
		for _, label := range []string{"Total failed:", "Total banned:", "Banned IP list:"} {
			i := strings.Index(line, label)
			if i < 0 {
				continue
			}
			if seen[label] {
				return out, ErrUnavailable
			}
			seen[label] = true
			value := strings.TrimSpace(line[i+len(label):])
			if label == "Banned IP list:" {
				for _, ip := range strings.Fields(value) {
					a, e := netip.ParseAddr(ip)
					if e != nil || a.IsUnspecified() || a.IsMulticast() || slices.Contains(out.Banned, a.String()) || len(out.Banned) >= 32 {
						return out, ErrUnavailable
					}
					out.Banned = append(out.Banned, a.String())
				}
				continue
			}
			n, e := strconv.ParseInt(value, 10, 64)
			if e != nil || n < 0 {
				return out, ErrUnavailable
			}
			if label == "Total failed:" {
				out.FailedTotal = n
			} else {
				out.BannedTotal = n
			}
		}
	}
	if len(seen) != 3 {
		return out, ErrUnavailable
	}
	return out, nil
}
func ValidateFail2banWitness(w NativeFail2banWitness) error {
	for _, state := range []NativeFail2banState{w.Before, w.Banned, w.After} {
		if state.MaxRetry != 5 || state.FindTimeSeconds != 600 || state.BanTimeSeconds != 600 {
			return ErrUnavailable
		}
	}
	if len(w.Before.Banned) != 0 || len(w.Banned.Banned) != 1 || w.Banned.Banned[0] != w.Failures.SourceAddress || len(w.After.Banned) != 0 || w.Banned.FailedTotal-w.Before.FailedTotal != 5 || w.After.FailedTotal != w.Banned.FailedTotal || w.Banned.BannedTotal-w.Before.BannedTotal != 1 || w.After.BannedTotal != w.Banned.BannedTotal || w.ElapsedNanoseconds < int64(600*time.Second) {
		return ErrUnavailable
	}
	if !w.Failures.HostKeyVerified || len(w.Failures.Outcomes) != 5 {
		return ErrUnavailable
	}
	for _, out := range w.Failures.Outcomes {
		if out != "denied" {
			return ErrUnavailable
		}
	}
	if w.Failures.DestinationHostID != w.AdminBefore.DestinationHostID || w.Failures.DestinationIdentityDigest != w.AdminBefore.DestinationIdentityDigest {
		return ErrUnavailable
	}
	admin := w.AdminBefore.SourceAddress
	for _, ob := range []NativeSSHObservation{w.AdminBefore, w.AdminDuring, w.AdminAfter} {
		if admin == "" || ob.SourceAddress != admin || ob.SourceAddress == w.Failures.SourceAddress || !ob.HostKeyVerified || len(ob.Outcomes) != 1 || ob.Outcomes[0] != "allowed" || ob.NamespaceDigest != w.AdminBefore.NamespaceDigest || ob.RouteDigest != w.AdminBefore.RouteDigest || ob.SourceHostID != w.AdminBefore.SourceHostID || ob.SourceIdentityDigest != w.AdminBefore.SourceIdentityDigest || ob.DestinationHostID != w.AdminBefore.DestinationHostID || ob.DestinationIdentityDigest != w.AdminBefore.DestinationIdentityDigest || ob.DestinationAddress != w.AdminBefore.DestinationAddress || ob.DestinationPort != w.AdminBefore.DestinationPort || ob.User != w.AdminBefore.User || ob.PublicKeyDigest != w.AdminBefore.PublicKeyDigest || ob.InputDigest != w.AdminBefore.InputDigest {
			return ErrUnavailable
		}
	}
	before, e := time.Parse(time.RFC3339Nano, w.Before.ObservedAt)
	ban, f := time.Parse(time.RFC3339Nano, w.Banned.ObservedAt)
	after, g := time.Parse(time.RFC3339Nano, w.After.ObservedAt)
	if e != nil || f != nil || g != nil || !ban.After(before) || after.Sub(ban) < 600*time.Second {
		return ErrUnavailable
	}
	attempted, x := time.Parse(time.RFC3339Nano, w.Failures.ObservedAt)
	adminBefore, y := time.Parse(time.RFC3339Nano, w.AdminBefore.ObservedAt)
	adminAfter, z := time.Parse(time.RFC3339Nano, w.AdminAfter.ObservedAt)
	if x != nil || y != nil || z != nil || attempted.Before(before) || attempted.After(ban) || adminBefore.Before(before) || adminBefore.After(attempted) || adminAfter.Before(after) {
		return ErrUnavailable
	}
	during, h := time.Parse(time.RFC3339Nano, w.AdminDuring.ObservedAt)
	if h != nil || during.Before(ban) || !during.Before(after) {
		return ErrUnavailable
	}
	return nil
}
