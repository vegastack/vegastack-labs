//go:build linux

package ingressconnector

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"github.com/vegastack/vegastack-labs/internal/strictjson"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type native struct {
	root         string
	uid          uint32
	run          func(context.Context, []string) ([]byte, error)
	fetch        func(context.Context, io.Writer) error
	binaryDigest string
	process      func(int64) error
}

func NewNativeRuntime() Runtime {
	return &native{root: "/", uid: 0, run: systemctl, fetch: download, binaryDigest: BinarySHA256, process: verifyProcess}
}

type commandOutput struct{ bytes.Buffer }

func (b *commandOutput) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 65536 {
		return 0, denied()
	}
	return b.Buffer.Write(p)
}
func systemctl(ctx context.Context, args []string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, "/usr/bin/systemctl", args...)
	c.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	c.Dir = "/"
	var b commandOutput
	c.Stdout = &b
	c.Stderr = io.Discard
	if c.Run() != nil || b.Len() > 65536 {
		return nil, denied()
	}
	return b.Bytes(), nil
}
func download(ctx context.Context, w io.Writer) error {
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	client := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 90 * time.Second, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		if len(via) > 3 || r.URL.Scheme != "https" || (r.URL.Host != "github.com" && r.URL.Host != "release-assets.githubusercontent.com" && r.URL.Host != "objects.githubusercontent.com") {
			return denied()
		}
		return nil
	}}
	q, e := http.NewRequestWithContext(ctx, "GET", BinaryURL, nil)
	if e != nil {
		return denied()
	}
	r, e := client.Do(q)
	if e != nil {
		return denied()
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return denied()
	}
	n, e := io.Copy(w, io.LimitReader(r.Body, (100<<20)+1))
	if e != nil || n < 1 || n > 100<<20 {
		return denied()
	}
	return nil
}
func (n *native) path(p string) string { return filepath.Join(n.root, strings.TrimPrefix(p, "/")) }

// Every ancestor must be an owned directory without write access for other users.
func (n *native) stat(p string) (os.FileInfo, error) {
	parts := strings.Split(strings.TrimPrefix(p, "/"), "/")
	for i := range parts {
		q := n.path("/" + strings.Join(parts[:i+1], "/"))
		st, e := os.Lstat(q)
		if e != nil {
			return nil, e
		}
		s, ok := st.Sys().(*syscall.Stat_t)
		if !ok || s.Uid != n.uid || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm()&0022 != 0 || (i < len(parts)-1 && !st.IsDir()) {
			return nil, denied()
		}
		if i == len(parts)-1 {
			return st, nil
		}
	}
	return nil, denied()
}
func (n *native) artifact(p string, mode os.FileMode, max int64, read bool) ([]byte, error) {
	st, e := n.stat(p)
	if os.IsNotExist(e) {
		return nil, e
	}
	if e != nil || !st.Mode().IsRegular() || st.Mode().Perm() != mode || st.Size() < 1 || st.Size() > max {
		return nil, denied()
	}
	s := st.Sys().(*syscall.Stat_t)
	if s.Nlink != 1 {
		return nil, denied()
	}
	if !read {
		return nil, nil
	}
	f, e := os.Open(n.path(p))
	if e != nil {
		return nil, denied()
	}
	defer f.Close()
	actual, e := f.Stat()
	if e != nil || !os.SameFile(st, actual) {
		return nil, denied()
	}
	b, e := io.ReadAll(io.LimitReader(f, max+1))
	if e != nil || int64(len(b)) > max {
		return nil, denied()
	}
	return b, nil
}
func hash(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func (n *native) prerequisites(in Input) error {
	if e := n.checkToken(in); e != nil {
		return denied()
	}
	if in.OriginCADigest != "" {
		parts := strings.Split(strings.TrimPrefix(filepath.Dir(CAPath), "/"), "/")
		for i := range parts {
			st, e := n.stat("/" + strings.Join(parts[:i+1], "/"))
			if e != nil || st.Mode().Perm()&0001 == 0 {
				return denied()
			}
		}
		b, e := n.artifact(CAPath, 0644, 65536, true)
		if e != nil || "sha256:"+hash(b) != in.OriginCADigest {
			return denied()
		}
		count := 0
		for len(bytes.TrimSpace(b)) > 0 {
			if !bytes.HasPrefix(bytes.TrimSpace(b), []byte("-----BEGIN CERTIFICATE-----")) {
				return denied()
			}
			block, rest := pem.Decode(b)
			if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
				return denied()
			}
			c, e := x509.ParseCertificate(block.Bytes)
			if e != nil || !c.IsCA || time.Now().Before(c.NotBefore) || !time.Now().Before(c.NotAfter) {
				return denied()
			}
			count++
			b = rest
		}
		if count == 0 {
			return denied()
		}
	}
	return nil
}
func (n *native) installFile(p string, b []byte, mode os.FileMode) error {
	if _, e := n.stat(filepath.Dir(p)); e != nil {
		return denied()
	}
	f, e := os.CreateTemp(n.path(filepath.Dir(p)), ".vsk-ingress-*")
	if e != nil {
		return denied()
	}
	name := f.Name()
	defer os.Remove(name)
	if f.Chmod(mode) != nil {
		f.Close()
		return denied()
	}
	if _, e = f.Write(b); e != nil {
		f.Close()
		return denied()
	}
	if f.Sync() != nil || f.Close() != nil {
		return denied()
	}
	if e = os.Link(name, n.path(p)); e != nil {
		return denied()
	}
	return nil
}
func (n *native) Install(ctx context.Context, in Input) (out Result, err error) {
	raw, _ := json.Marshal(in)
	if _, e := Decode(raw); e != nil || ctx.Err() != nil || n.prerequisites(in) != nil {
		return out, denied()
	}
	// Refuse replacement, drop-ins or an existing unrelated unit before any mutation.
	unit := Unit(in)
	old, e := n.artifact(UnitPath, 0644, 65536, true)
	unitAbsent := os.IsNotExist(e)
	if e != nil && !unitAbsent {
		return out, denied()
	}
	if !unitAbsent && !bytes.Equal(old, unit) {
		return out, denied()
	}
	if unitAbsent {
		for _, args := range [][]string{{"list-units", "--all", "--plain", "--no-legend", "--no-pager", UnitName}, {"list-unit-files", "--no-legend", "--no-pager", UnitName}} {
			b, e := n.run(ctx, args)
			if e != nil || len(bytes.TrimSpace(b)) != 0 {
				return out, denied()
			}
		}
	}
	if _, e = os.Lstat(n.path(UnitPath + ".d")); e == nil || !os.IsNotExist(e) {
		return out, denied()
	}
	if _, e := n.stat(filepath.Dir(BinaryPath)); e != nil {
		return out, denied()
	}

	binary, e := n.artifact(BinaryPath, 0755, 100<<20, true)
	binaryAbsent := os.IsNotExist(e)
	if e != nil && !binaryAbsent {
		return out, denied()
	}
	if !binaryAbsent && hash(binary) != n.binaryDigest {
		return out, denied()
	}
	if binaryAbsent {
		var b bytes.Buffer
		if n.fetch(ctx, &b) != nil || hash(b.Bytes()) != n.binaryDigest {
			return out, denied()
		}
		if e = n.installFile(BinaryPath, b.Bytes(), 0755); e != nil {
			return out, e
		}
		out.Changed = true
	}
	if unitAbsent {
		if e = n.installFile(UnitPath, unit, 0644); e != nil {
			return out, e
		}
		out.Changed = true
	}
	if n.prerequisites(in) != nil {
		return out, denied()
	}
	for _, args := range [][]string{{"daemon-reload"}, {"enable", UnitName}, {"start", UnitName}} {
		out.Changed = true
		if _, e = n.run(ctx, args); e != nil {
			return out, denied()
		}
	}
	props, e := n.run(ctx, []string{"show", UnitName, "--property=ActiveState,SubState,MainPID,FragmentPath,DropInPaths,DynamicUser", "--no-pager"})
	if e != nil {
		return out, denied()
	}
	p := map[string]string{}
	for _, line := range strings.Split(string(props), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if ok {
			p[k] = v
		}
	}
	pid, _ := strconv.ParseInt(p["MainPID"], 10, 64)
	if p["ActiveState"] != "active" || p["SubState"] != "running" || pid <= 0 || n.process == nil || n.process(pid) != nil || p["FragmentPath"] != UnitPath || p["DropInPaths"] != "" || p["DynamicUser"] != "yes" {
		return out, denied()
	}
	actual, e := n.artifact(UnitPath, 0644, 65536, true)
	if e != nil || !bytes.Equal(actual, unit) || n.prerequisites(in) != nil {
		return out, denied()
	}
	out.Verified = true
	return out, nil
}

func verifyProcess(pid int64) error {
	p := "/proc/" + strconv.FormatInt(pid, 10) + "/exe"
	target, e := os.Readlink(p)
	if e != nil || target != BinaryPath {
		return denied()
	}
	f, e := os.Open(p)
	if e != nil {
		return denied()
	}
	defer f.Close()
	h := sha256.New()
	size, e := io.Copy(h, io.LimitReader(f, (100<<20)+1))
	if e != nil || size < 1 || size > 100<<20 || hex.EncodeToString(h.Sum(nil)) != BinarySHA256 {
		return denied()
	}
	return nil
}

// Format grounded in pinned cloudflared 2026.10.5 connection.TunnelToken and
// tunnel.ParseToken. This compares scope only; provider acceptance is separate.
func (n *native) checkToken(in Input) error {
	raw, e := n.artifact(TokenPath, 0600, 16384, true)
	if e != nil {
		return denied()
	}
	defer wipe(raw)
	encoded := bytes.TrimSpace(raw)
	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(encoded)))
	defer wipe(decoded)
	size, e := base64.StdEncoding.Decode(decoded, encoded)
	if e != nil {
		return denied()
	}
	decoded = decoded[:size]
	if strictjson.Scan(context.Background(), decoded, strictjson.Limits{MaxDepth: 2}) != nil {
		return denied()
	}
	var token struct {
		Account  string `json:"a"`
		Secret   []byte `json:"s"`
		Tunnel   string `json:"t"`
		Endpoint string `json:"e,omitempty"`
	}
	defer func() { wipe(token.Secret) }()
	d := json.NewDecoder(bytes.NewReader(decoded))
	d.DisallowUnknownFields()
	if d.Decode(&token) != nil || d.Decode(new(any)) != io.EOF || token.Account != in.AccountID || token.Tunnel != in.TunnelID || len(token.Secret) < 32 || len(token.Secret) > 4096 || token.Endpoint != "" {
		return denied()
	}
	return nil
}
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
