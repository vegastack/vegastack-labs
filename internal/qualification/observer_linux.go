//go:build linux

package qualification

import (
	"bufio"
	"context"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type nativeObserver struct {
	scope validatedNativeScope
	file  *os.File
	mu    sync.Mutex
}

func OpenNativeObserver(ctx context.Context, scope generated.QualificationScope) (NativeObserver, error) {
	installed, err := LoadServerScope(ctx)
	if err != nil || hostaction.Digest(installed) != hostaction.Digest(scope) {
		return nil, ErrUnavailable
	}
	s, err := validateScope(scope)
	if err != nil || validateControlAccount() != nil || scope.ControlServiceUID != int64(os.Geteuid()) || scope.ControlServiceGID != int64(os.Getegid()) {
		return nil, ErrUnavailable
	}
	const link = "/dev/virtio-ports/vsk.native.observer"
	for _, path := range []string{"/dev", "/dev/virtio-ports"} {
		i, e := os.Lstat(path)
		if e != nil || !i.IsDir() || i.Mode().Perm()&0022 != 0 {
			return nil, ErrUnavailable
		}
		u, ok := fileOwner(i)
		if !ok || u != 0 {
			return nil, ErrUnavailable
		}
	}
	info, err := os.Lstat(link)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		return nil, ErrUnavailable
	}
	uid, ok := fileOwner(info)
	if !ok || uid != 0 {
		return nil, ErrUnavailable
	}
	target, err := os.Readlink(link)
	if err != nil {
		return nil, err
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(filepath.Dir(link), target)
	}
	target = filepath.Clean(target)
	if !regexp.MustCompile(`^/dev/vport[0-9]+p[0-9]+$`).MatchString(target) {
		return nil, ErrUnavailable
	}
	fd, err := unix.Open(target, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), target)
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFCHR || st.Uid != 0 || st.Gid != uint32(os.Getegid()) || st.Mode&0777 != 0660 {
		f.Close()
		return nil, ErrUnavailable
	}
	return &nativeObserver{s, f, sync.Mutex{}}, nil
}
func validateControlAccount() error {
	if os.Geteuid() == 0 {
		return ErrUnavailable
	}
	read := func(path string) (string, error) {
		i, e := os.Lstat(path)
		if e != nil || !i.Mode().IsRegular() || i.Mode().Perm()&0022 != 0 || i.Size() > 131072 {
			return "", ErrUnavailable
		}
		uid, ok := fileOwner(i)
		if !ok || uid != 0 {
			return "", ErrUnavailable
		}
		b, e := os.ReadFile(path)
		return string(b), e
	}
	passwd, err := read("/etc/passwd")
	if err != nil {
		return err
	}
	group, err := read("/etc/group")
	if err != nil {
		return err
	}
	uid, gid := strconv.Itoa(os.Geteuid()), strconv.Itoa(os.Getegid())
	found := false
	for _, line := range strings.Split(passwd, "\n") {
		if line == "" {
			continue
		}
		v := strings.Split(line, ":")
		if len(v) != 7 {
			return ErrUnavailable
		}
		if v[0] == "vsk-labs" {
			if found || v[2] != uid || v[3] != gid {
				return ErrUnavailable
			}
			found = true
		} else if v[2] == uid || v[3] == gid {
			return ErrUnavailable
		}
	}
	if !found {
		return ErrUnavailable
	}
	found = false
	for _, line := range strings.Split(group, "\n") {
		if line == "" {
			continue
		}
		v := strings.Split(line, ":")
		if len(v) != 4 {
			return ErrUnavailable
		}
		if v[2] == gid {
			if found || v[0] != "vsk-labs" || (v[3] != "" && v[3] != "vsk-labs") {
				return ErrUnavailable
			}
			found = true
		}
	}
	if !found {
		return ErrUnavailable
	}
	return nil
}
func (o *nativeObserver) Close() error { return o.file.Close() }
func (o *nativeObserver) Observe(ctx context.Context, b generated.NativeObservationBinding) (generated.NativeObservation, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	var out generated.NativeObservation
	raw, err := json.Marshal(b)
	if err != nil || generated.ValidateContractJSON(generated.SchemaIDNativeObservationBinding, raw, generated.ContractExact) != nil {
		return out, ErrUnavailable
	}
	r := generated.NativeStepRequest{Schema: generated.SchemaIDNativeStepRequest, SchemaVersion: "1.0.0", ScopeDigest: b.ScopeDigest, GuestID: b.GuestID, ScenarioID: b.ScenarioID, Ordinal: b.Ordinal, ControllerInstanceID: b.ControllerInstanceID, RecoveryEpoch: b.RecoveryEpoch, PlanID: b.PlanID, PlanDigest: b.PlanDigest, RunID: b.RunID, StepID: b.StepID, LeaseID: b.LeaseID, Nonce: b.Nonce, Deadline: b.Deadline, Operation: "observe"}
	if validateStep(o.scope, r, time.Now().UTC()) != nil {
		return out, ErrUnavailable
	}
	deadline := time.Now().Add(30 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if o.file.SetDeadline(deadline) != nil {
		return out, ErrUnavailable
	}
	stop := context.AfterFunc(ctx, func() { o.file.SetDeadline(time.Now()) })
	defer stop()
	if _, err = o.file.Write(append(raw, '\n')); err != nil {
		return out, err
	}
	reader := bufio.NewReaderSize(o.file, 256*1024)
	line, err := reader.ReadSlice('\n')
	if err != nil || len(line) > 256*1024 || generated.ValidateContractJSON(generated.SchemaIDNativeObservation, line, generated.ContractExact) != nil || json.Unmarshal(line, &out) != nil {
		return out, ErrUnavailable
	}
	if hostaction.Digest(out.Binding) != hostaction.Digest(b) || out.ExecutableDigest != o.scope.value.ExecutableDigest || out.ChannelDigest != o.scope.value.ConsoleReferenceDigest || !bootIDPattern.MatchString(out.BootID) {
		return generated.NativeObservation{}, ErrUnavailable
	}
	at, err := time.Parse(time.RFC3339, out.ObservedAt)
	if err != nil || time.Since(at) > 30*time.Second || at.After(time.Now().Add(time.Second)) {
		return generated.NativeObservation{}, ErrUnavailable
	}
	return out, nil
}
