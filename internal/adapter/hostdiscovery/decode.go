// Package hostdiscovery contains only bounded, read-only host inspection.
package hostdiscovery

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/vegastack/vegastack-labs/internal/generated"
	domain "github.com/vegastack/vegastack-labs/internal/hostdiscovery"
	"github.com/vegastack/vegastack-labs/internal/strictjson"
)

const MaxOutput = 64 << 10

var simple = regexp.MustCompile(`^[A-Za-z0-9_.:+-]{1,256}$`)
var machineID = regexp.MustCompile(`^[0-9a-f]{32}$`)
var uuid = regexp.MustCompile(`^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$`)
var version = regexp.MustCompile(`^[0-9]+(\.[0-9]+){0,3}$`)

func invalid() error { return domain.Error(generated.ErrorCodeInputInvalid) }
func safeText(s string) bool {
	if s == "" || len(s) > 256 || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
func Decode(operation string, raw []byte) (domain.Facts, error) {
	if len(raw) > MaxOutput || !utf8.Valid(raw) || bytes.IndexByte(raw, 0) >= 0 {
		return nil, invalid()
	}
	text := strings.TrimSpace(string(raw))
	facts := domain.Facts{}
	add := func(name, value string) { facts = append(facts, domain.Fact(name, value, operation)) }
	switch operation {
	case "os-release":
		values := map[string]string{}
		for _, line := range strings.Split(text, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			key, value, ok := strings.Cut(line, "=")
			if !ok || !simple.MatchString(key) {
				return nil, invalid()
			}
			if _, exists := values[key]; exists {
				return nil, invalid()
			}
			if strings.HasPrefix(value, "\"") {
				decoded, err := strconv.Unquote(value)
				if err != nil {
					return nil, invalid()
				}
				value = decoded
			} else if strings.HasPrefix(value, "'") {
				if len(value) < 2 || value[len(value)-1] != '\'' || strings.Contains(value[1:len(value)-1], "'") {
					return nil, invalid()
				}
				value = value[1 : len(value)-1]
			}
			if !safeText(value) {
				return nil, invalid()
			}
			values[key] = value
		}
		if !simple.MatchString(values["ID"]) || !version.MatchString(values["VERSION_ID"]) {
			return nil, invalid()
		}
		add("os.id", values["ID"])
		add("os.version", values["VERSION_ID"])
	case "debian-version":
		if !version.MatchString(text) || len(text) > 32 {
			return nil, invalid()
		}
		add("os.point-version", text)
	case "architecture":
		if !simple.MatchString(text) {
			return nil, invalid()
		}
		if text == "x86_64" {
			text = "amd64"
		}
		if text == "aarch64" {
			text = "arm64"
		}
		add("architecture", text)
	case "machine-id":
		if !machineID.MatchString(text) || text == strings.Repeat("0", 32) {
			return nil, invalid()
		}
		add(operation, text)
	case "product-uuid":
		if !uuid.MatchString(text) || strings.ReplaceAll(text, "-", "") == strings.Repeat("0", 32) {
			return nil, invalid()
		}
		add(operation, strings.ToLower(text))
	case "product-serial":
		if !safeText(text) {
			return nil, invalid()
		}
		add(operation, text)
	case "memory":
		found := false
		for _, line := range strings.Split(text, "\n") {
			if !strings.HasPrefix(line, "MemTotal:") {
				continue
			}
			fields := strings.Fields(line)
			if found || len(fields) != 3 || fields[2] != "kB" {
				return nil, invalid()
			}
			n, err := strconv.ParseInt(fields[1], 10, 64)
			if err != nil || n <= 0 || n > math.MaxInt64/1024 {
				return nil, invalid()
			}
			found = true
			add("memory.bytes", strconv.FormatInt(n*1024, 10))
		}
		if !found {
			return nil, invalid()
		}
	case "cpu-online":
		seen := map[int]bool{}
		for _, item := range strings.Split(text, ",") {
			bounds := strings.Split(item, "-")
			if len(bounds) > 2 {
				return nil, invalid()
			}
			start, err := strconv.Atoi(bounds[0])
			if err != nil || start < 0 || start >= 65536 {
				return nil, invalid()
			}
			end := start
			if len(bounds) == 2 {
				end, err = strconv.Atoi(bounds[1])
				if err != nil || end < start || end >= 65536 {
					return nil, invalid()
				}
			}
			for n := start; n <= end; n++ {
				if seen[n] {
					return nil, invalid()
				}
				seen[n] = true
			}
		}
		add("cpu.logical-count", strconv.Itoa(len(seen)))
	case "block-devices":
		var input struct {
			Devices []blockDevice `json:"blockdevices"`
		}
		if strictDecode(raw, &input) != nil || input.Devices == nil {
			return nil, invalid()
		}
		total := 0
		names := map[string]bool{}
		var visit func([]blockDevice) error
		visit = func(devices []blockDevice) error {
			for _, d := range devices {
				total++
				if total > 128 || !simple.MatchString(d.Name) || !simple.MatchString(d.Type) || names[d.Name] {
					return invalid()
				}
				names[d.Name] = true
				n, err := strconv.ParseInt(string(d.Size), 10, 64)
				if err != nil || n < 0 {
					return invalid()
				}
				prefix := fmt.Sprintf("device.%d.", total-1)
				add(prefix+"name", d.Name)
				add(prefix+"type", d.Type)
				add(prefix+"bytes", strconv.FormatInt(n, 10))
				if err := visit(d.Children); err != nil {
					return err
				}
			}
			return nil
		}
		if err := visit(input.Devices); err != nil {
			return nil, err
		}
		add("device.count", strconv.Itoa(total))
	case "interfaces":
		var interfaces []map[string]json.RawMessage
		if strictDecode(raw, &interfaces) != nil || interfaces == nil || len(interfaces) > 64 {
			return nil, invalid()
		}
		allowed := map[string]bool{"ifindex": true, "ifname": true, "flags": true, "mtu": true, "qdisc": true, "operstate": true, "linkmode": true, "group": true, "txqlen": true, "link_type": true, "address": true, "broadcast": true, "link_index": true, "link_netnsid": true, "master": true, "altnames": true, "promiscuity": true, "allmulti": true, "min_mtu": true, "max_mtu": true, "num_tx_queues": true, "num_rx_queues": true, "gso_max_size": true, "gso_max_segs": true, "tso_max_size": true, "tso_max_segs": true, "gro_max_size": true, "gso_ipv4_max_size": true, "gro_ipv4_max_size": true}
		names := map[string]bool{}
		for i, item := range interfaces {
			for key := range item {
				if !allowed[key] {
					return nil, invalid()
				}
			}
			var name, kind, mac string
			if json.Unmarshal(item["ifname"], &name) != nil || json.Unmarshal(item["link_type"], &kind) != nil || !simple.MatchString(name) || !simple.MatchString(kind) || names[name] {
				return nil, invalid()
			}
			names[name] = true
			prefix := fmt.Sprintf("interface.%d.", i)
			add(prefix+"name", name)
			add(prefix+"type", kind)
			if value, ok := item["address"]; ok {
				if json.Unmarshal(value, &mac) != nil {
					return nil, invalid()
				}
				parsed, err := net.ParseMAC(mac)
				if err != nil {
					return nil, invalid()
				}
				add(prefix+"mac", parsed.String())
			}
		}
		add("interface.count", strconv.Itoa(len(interfaces)))
	default:
		return nil, invalid()
	}
	return facts, nil
}

type blockDevice struct {
	Name     string        `json:"name"`
	Type     string        `json:"type"`
	Size     json.Number   `json:"size"`
	Children []blockDevice `json:"children,omitempty"`
}

func strictDecode(raw []byte, out any) error {
	if strictjson.Scan(context.Background(), raw, strictjson.Limits{MaxDepth: 16}) != nil {
		return invalid()
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(out) != nil {
		return invalid()
	}
	return nil
}
