//go:build linux || darwin

package debianbaseline

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path"
	"strings"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/strictjson"
	"golang.org/x/sys/unix"
)

// VolumeRecoveryPolicy is an inert administrator-installed selector. It holds
// no recovery material. Header/key filenames are fixed beneath this reference.
type VolumeRecoveryPolicy struct {
	Version          string `json:"version"`
	ReferenceID      string `json:"referenceId"`
	MaterialVersion  string `json:"materialVersion"`
	BindingDigest    string `json:"bindingDigest"`
	CryptsetupDigest string `json:"cryptsetupDigest"`
}

func volumePolicyBinding(b generated.HostVolumeBinding) string {
	b.RecoveryReferenceDigest = ""
	return hostaction.Digest(b)
}

// PrepareVolumeRecoveryPolicy returns bytes only. The administrator separately
// installs these alongside the already-held private header and key. The returned
// policy digest must be acknowledged in Binding.RecoveryReferenceDigest.
func PrepareVolumeRecoveryPolicy(in generated.VolumeRecoveryInput, cryptsetupDigest string) ([]byte, string, error) {
	if ValidateVolumeBinding(in.Binding) != nil || !safeName.MatchString(in.RecoveryReferenceID) || !safeName.MatchString(in.RecoveryMaterialVersion) || !volumeDigest(cryptsetupDigest) {
		return nil, "", errVolume
	}
	p := VolumeRecoveryPolicy{Version: "1.0.0", ReferenceID: in.RecoveryReferenceID, MaterialVersion: in.RecoveryMaterialVersion, BindingDigest: volumePolicyBinding(in.Binding), CryptsetupDigest: cryptsetupDigest}
	raw, e := json.Marshal(p)
	return raw, hostaction.Digest(p), e
}
func volumeDigest(v string) bool {
	if len(v) != 71 || !strings.HasPrefix(v, "sha256:") {
		return false
	}
	for _, c := range v[7:] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// Walk each ancestor by descriptor, rejecting symlinks and writable/unowned
// directories. Private files additionally forbid other-reader bits/hardlinks.
func openVolumeProtected(root, name string, uid uint32, private bool) (*os.File, error) {
	if name == "" || path.Clean(name) != name || strings.HasPrefix(name, "/") || strings.Contains(name, "\\") {
		return nil, errVolume
	}
	parts := strings.Split(name, "/")
	for _, v := range parts {
		if v == "." || v == ".." || v == "" {
			return nil, errVolume
		}
	}
	fd, e := unix.Open(root, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if e != nil {
		return nil, errVolume
	}
	for i, part := range parts {
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || st.Uid != uid || st.Mode&0022 != 0 {
			unix.Close(fd)
			return nil, errVolume
		}
		flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK
		if i < len(parts)-1 {
			flags |= unix.O_DIRECTORY
		}
		next, e := unix.Openat(fd, part, flags, 0)
		unix.Close(fd)
		if e != nil {
			return nil, errVolume
		}
		fd = next
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Uid != uid || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Mode&0022 != 0 || private && st.Mode&0077 != 0 {
		unix.Close(fd)
		return nil, errVolume
	}
	return os.NewFile(uintptr(fd), path.Join(root, name)), nil
}
func readVolumeBounded(f *os.File, maximum int64) ([]byte, error) {
	if _, e := f.Seek(0, io.SeekStart); e != nil {
		return nil, errVolume
	}
	raw, e := io.ReadAll(io.LimitReader(f, maximum+1))
	if e != nil || int64(len(raw)) > maximum {
		return nil, errVolume
	}
	return raw, nil
}
func loadVolumePolicy(ctx context.Context, root string, uid uint32, in generated.VolumeRecoveryInput) (VolumeRecoveryPolicy, error) {
	var p VolumeRecoveryPolicy
	if ctx == nil || ctx.Err() != nil || !safeName.MatchString(in.RecoveryReferenceID) {
		return p, errVolume
	}
	f, e := openVolumeProtected(root, "etc/vsk-labs/volume-recovery/"+in.RecoveryReferenceID+"/policy.json", uid, true)
	if e != nil {
		return p, e
	}
	defer f.Close()
	raw, e := readVolumeBounded(f, 8192)
	if e != nil || strictjson.Scan(ctx, raw, strictjson.Limits{MaxDepth: 4}) != nil {
		return p, errVolume
	}
	d := json.NewDecoder(strings.NewReader(string(raw)))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil || p.Version != "1.0.0" || p.ReferenceID != in.RecoveryReferenceID || p.MaterialVersion != in.RecoveryMaterialVersion || p.BindingDigest != volumePolicyBinding(in.Binding) || hostaction.Digest(p) != in.Binding.RecoveryReferenceDigest || !volumeDigest(p.CryptsetupDigest) {
		return p, errVolume
	}
	return p, nil
}
