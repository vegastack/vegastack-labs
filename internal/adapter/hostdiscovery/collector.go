package hostdiscovery

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	domain "github.com/vegastack/vegastack-labs/internal/hostdiscovery"
	"golang.org/x/crypto/ssh"
)

var commands = []struct{ operation, command string }{
	{"os-release", "/usr/bin/cat /etc/os-release"}, {"debian-version", "/usr/bin/cat /etc/debian_version"},
	{"architecture", "/usr/bin/uname -m"}, {"machine-id", "/usr/bin/cat /etc/machine-id"},
	{"product-uuid", "/usr/bin/cat /sys/class/dmi/id/product_uuid"}, {"product-serial", "/usr/bin/cat /sys/class/dmi/id/product_serial"},
	{"memory", "/usr/bin/cat /proc/meminfo"}, {"cpu-online", "/usr/bin/cat /sys/devices/system/cpu/online"},
	{"block-devices", "/usr/bin/lsblk --json --bytes --output NAME,TYPE,SIZE"}, {"interfaces", "/usr/bin/ip -j link show"},
}

type CredentialBorrower interface {
	Check(context.Context, domain.Target) error
	Borrow(context.Context, domain.Target) (*credentialref.Value, error)
}
type Collector struct {
	Borrower CredentialBorrower
	Clock    func() time.Time
}

func (c *Collector) Collect(ctx context.Context, target domain.Target) (domain.Collection, error) {
	result := domain.Collection{Facts: domain.Facts{}, Missing: []string{}}
	if c == nil || c.Borrower == nil || ctx == nil || domain.ValidateTarget(target.Binding) != nil || target.StateRevision < 1 || target.GrantRevision < 1 {
		return result, domain.Error(generated.ErrorCodePrerequisiteBlocked)
	}
	ctx, cancel := context.WithTimeout(ctx, domain.MaximumDuration)
	defer cancel()
	if c.Borrower.Check(ctx, target) != nil {
		return domain.Collection{}, domain.Error(generated.ErrorCodePrerequisiteBlocked)
	}
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(target.Binding.HostKey))
	if err != nil {
		return result, invalid()
	}
	address := net.JoinHostPort(target.Binding.Address, strconv.FormatInt(target.Binding.Port, 10))
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	if err != nil {
		return domain.Collection{}, collectionFailure(ctx)
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if conn.SetDeadline(deadline) != nil {
		return domain.Collection{}, collectionFailure(ctx)
	}
	var borrowed *credentialref.Value
	publicKeyReady := false
	defer func() {
		if borrowed != nil {
			borrowed.Close()
		}
	}()
	config := &ssh.ClientConfig{User: target.Binding.User, HostKeyCallback: ssh.FixedHostKey(key), Auth: []ssh.AuthMethod{ssh.PublicKeysCallback(func() ([]ssh.Signer, error) {
		if borrowed != nil {
			return nil, domain.Error(generated.ErrorCodePrerequisiteBlocked)
		}
		var err error
		borrowed, err = c.Borrower.Borrow(ctx, target)
		if err != nil || borrowed == nil {
			return nil, domain.Error(generated.ErrorCodePrerequisiteBlocked)
		}
		signer, err := ssh.ParsePrivateKey(borrowed.Bytes())
		if err != nil {
			return nil, domain.Error(generated.ErrorCodePrerequisiteBlocked)
		}
		publicKeyReady = true
		return []ssh.Signer{signer}, nil
	})}}
	secure, channels, requests, err := ssh.NewClientConn(conn, address, config)
	if err != nil {
		return domain.Collection{}, collectionFailure(ctx)
	}
	if !publicKeyReady {
		_ = secure.Close()
		return domain.Collection{}, domain.Error(generated.ErrorCodePrerequisiteBlocked)
	}
	client := ssh.NewClient(secure, channels, requests)
	defer client.Close()
	budget := &outputBudget{cancel: cancel}
	for _, command := range commands {
		commandCtx, stopCommand := context.WithTimeout(ctx, 5*time.Second)
		stopClose := context.AfterFunc(commandCtx, func() { _ = conn.Close() })
		session, err := client.NewSession()
		if err != nil {
			stopClose()
			stopCommand()
			return domain.Collection{}, collectionFailure(ctx)
		}
		stdout := &boundedOutput{budget: budget, keep: true}
		stderr := &boundedOutput{budget: budget}
		session.Stdout = stdout
		session.Stderr = stderr
		session.Stdin = nil
		err = session.Run(command.command)
		expired := commandCtx.Err() != nil
		stopClose()
		stopCommand()
		_ = session.Close()
		if budget.isExceeded() || expired || ctx.Err() != nil {
			return domain.Collection{}, collectionFailure(ctx)
		}
		if err != nil {
			var exit *ssh.ExitError
			if !errors.As(err, &exit) {
				return domain.Collection{}, collectionFailure(ctx)
			}
			result.Missing = append(result.Missing, command.operation)
			continue
		}
		facts, err := Decode(command.operation, stdout.buffer.Bytes())
		if err != nil {
			return domain.Collection{}, invalid()
		}
		captured := time.Now().UTC()
		if c.Clock != nil {
			captured = c.Clock().UTC()
		}
		for i := range facts {
			facts[i].CapturedAt = captured.Truncate(time.Second).Format(time.RFC3339)
		}
		result.Facts = append(result.Facts, facts...)
	}
	if err := domain.ValidateCollection(result); err != nil {
		return domain.Collection{}, err
	}
	return result, nil
}
func collectionFailure(ctx context.Context) error {
	if ctx.Err() != nil {
		return domain.Error(generated.ErrorCodeInterrupted)
	}
	return domain.Error(generated.ErrorCodeDependencyUnavailable)
}

type outputBudget struct {
	mu       sync.Mutex
	total    int
	exceeded bool
	cancel   context.CancelFunc
}
type boundedOutput struct {
	budget *outputBudget
	count  int
	keep   bool
	buffer bytes.Buffer
}

func (w *boundedOutput) Write(p []byte) (int, error) {
	w.budget.mu.Lock()
	defer w.budget.mu.Unlock()
	if w.count+len(p) > MaxOutput || w.budget.total+len(p) > 512<<10 {
		w.budget.exceeded = true
		w.budget.cancel()
		return 0, io.ErrShortBuffer
	}
	w.count += len(p)
	w.budget.total += len(p)
	if w.keep {
		return w.buffer.Write(p)
	}
	return len(p), nil
}

func (b *outputBudget) isExceeded() bool { b.mu.Lock(); defer b.mu.Unlock(); return b.exceeded }
