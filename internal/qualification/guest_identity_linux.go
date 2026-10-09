//go:build linux

package qualification

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostadoption"
	"github.com/vegastack/vegastack-labs/internal/hostreplacement"
	"io"
	"os"
	"strings"
	"syscall"
)

func verifyLocalGuest(guest generated.QualificationGuest) error {
	file, err := os.Open("/sys/class/dmi/id/product_serial")
	if err != nil {
		return err
	}
	raw, err := io.ReadAll(io.LimitReader(file, 513))
	file.Close()
	if err != nil || len(raw) > 512 {
		return ErrUnavailable
	}
	serial := strings.TrimSpace(string(raw))
	if serial != guest.InstanceID || hostadoption.IdentityDigest("product-serial", serial) != guest.HostIdentityDigest {
		return ErrUnavailable
	}
	path := "/etc/ssh/ssh_host_ed25519_key.pub"
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Size() > 4096 {
		return ErrUnavailable
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 || st.Nlink != 1 {
		return ErrUnavailable
	}
	key, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	digest, err := hostreplacement.SSHHostKeyDigest(string(key))
	if err != nil || digest != guest.SSHHostKeyDigest {
		return ErrUnavailable
	}
	return nil
}
