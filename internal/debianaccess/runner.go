package debianaccess

import (
	"bytes"
	"context"
	"io"
	"os/exec"
	"time"
)

type commandRunner func(context.Context, string, []string, []byte) ([]byte, error)
type boundedOutput struct{ bytes.Buffer }

func (b *boundedOutput) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 65536 {
		return 0, errAccess
	}
	return b.Buffer.Write(p)
}
func nativeCommand(ctx context.Context, bin string, args []string, stdin []byte) ([]byte, error) {
	switch bin {
	case "/usr/sbin/sshd", "/usr/sbin/useradd", "/usr/sbin/groupadd", "/usr/sbin/iptables-nft", "/usr/sbin/ip6tables-nft", "/usr/sbin/iptables-nft-restore", "/usr/sbin/ip6tables-nft-restore", "/usr/bin/systemctl", "/usr/bin/dpkg-query", "/usr/bin/cvtsudoers":
	default:
		return nil, errAccess
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, bin, args...)
	c.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	c.Dir = "/"
	c.Stdin = bytes.NewReader(stdin)
	var output boundedOutput
	c.Stdout = &output
	c.Stderr = io.Discard
	if err := c.Run(); err != nil {
		return nil, errAccess
	}
	return output.Bytes(), nil
}
