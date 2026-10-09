//go:build linux || darwin

package debianbaseline

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

func (n *nativeRuntime) timeObservation(ctx context.Context, sync []byte) ([]byte, error) {
	if strings.TrimSpace(string(sync)) != "yes" {
		return nil, errBaseline
	}
	raw, e := n.run(ctx, "/usr/bin/busctl", []string{"--json=short", "get-property", "org.freedesktop.timesync1", "/org/freedesktop/timesync1", "org.freedesktop.timesync1.Manager", "NTPMessage"}, nil)
	if e != nil {
		return nil, e
	}
	var m struct {
		Type string            `json:"type"`
		Data []json.RawMessage `json:"data"`
	}
	if json.Unmarshal(raw, &m) != nil || m.Type != "(uuuuittayttttbtt)" {
		return nil, errBaseline
	}
	var fields []json.RawMessage
	if len(m.Data) == 1 {
		if json.Unmarshal(m.Data[0], &fields) != nil {
			return nil, errBaseline
		}
	} else {
		fields = m.Data
	}
	if len(fields) != 15 {
		return nil, errBaseline
	}
	var t [4]int64
	for i := range t {
		if json.Unmarshal(fields[8+i], &t[i]) != nil || t[i] <= 0 {
			return nil, errBaseline
		}
	}
	var ignored bool
	if json.Unmarshal(fields[12], &ignored) != nil || ignored {
		return nil, errBaseline
	}
	offset := float64((t[1]-t[0])+(t[2]-t[3])) / 2e6
	return []byte(fmt.Sprintf("NTPSynchronized=yes\nOffsetSeconds=%f\n", offset)), nil
}
