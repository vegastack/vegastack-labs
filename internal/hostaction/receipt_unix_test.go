//go:build linux || darwin

package hostaction

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestReceiptClaimSurvivesReopen(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	first, err := OpenReceipts(root, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	if err = first.Claim(digest); err != nil {
		t.Fatal(err)
	}
	if err = first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := OpenReceipts(root, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if err = second.Claim(digest); err == nil {
		t.Fatal("replayed after reopen")
	}
}
func TestConcurrentReceiptHasOneWinner(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	var successes atomic.Int32
	var wg sync.WaitGroup
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := OpenReceipts(root, uint32(os.Geteuid()))
			if err != nil {
				t.Error(err)
				return
			}
			defer r.Close()
			if r.Claim("sha256:"+strings.Repeat("b", 64)) == nil {
				successes.Add(1)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatalf("winners=%d", successes.Load())
	}
}
func TestReceiptRejectsUnsafeDirectory(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	link := root + "/link"
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	if r, err := OpenReceipts(link, uint32(os.Geteuid())); err == nil {
		r.Close()
		t.Fatal("accepted symlink")
	}
	if err := os.Chmod(root, 0777); err != nil {
		t.Fatal(err)
	}
	if r, err := OpenReceipts(root, uint32(os.Geteuid())); err == nil {
		r.Close()
		t.Fatal("accepted unsafe modes")
	}
}

type fileHandler struct{ path string }

func (h fileHandler) Execute(_ context.Context, b generated.HostActionBundle) (generated.HostActionResult, error) {
	digest, _ := BundleDigest(b)
	err := os.WriteFile(h.path, []byte("exact action"), 0600)
	return generated.HostActionResult{Schema: generated.SchemaIDHostActionResult, SchemaVersion: "1.0.0", BundleDigest: digest, ResultDigest: BytesDigest([]byte("exact action")), Status: "succeeded", Changed: true, EffectObserved: true, Reason: "verified"}, err
}
func (h fileHandler) Verify(_ context.Context, _ generated.HostActionBundle, r generated.HostActionResult) error {
	raw, err := os.ReadFile(h.path)
	if err != nil || BytesDigest(raw) != r.ResultDigest {
		return blocked()
	}
	return nil
}

type testDispatcher struct{ handler Handler }

func (d testDispatcher) Lookup(id, version string) (Handler, bool) {
	return d.handler, id == "test.write-file" && version == "1.0.0"
}
func TestOnceRealPipeHandshakeAndDurableReplay(t *testing.T) {
	b, p, key, now := fixtureBundle(t)
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	receipts, err := OpenReceipts(root, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer receipts.Close()
	raw, err := SignEnvelope(b, p.KeyID, key)
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		if attempt == 1 {
			now = now.Add(time.Second)
			b.IssuedAt = now.Format(time.RFC3339)
			b.ExpiresAt = now.Add(time.Minute).Format(time.RFC3339)
			b.LeaseID = "fresh-lease"
			raw, err = SignEnvelope(b, p.KeyID, key)
			if err != nil {
				t.Fatal(err)
			}
		}
		inR, inW := io.Pipe()
		outR, outW := io.Pipe()
		done := make(chan error, 1)
		go func() {
			defer outW.Close()
			defer inR.Close()
			done <- RunOnce(context.Background(), inR, outW, p, receipts, testDispatcher{fileHandler{root + "/effect"}}, func() time.Time { return now }, rand.Reader)
		}()
		if _, err := inW.Write(append(raw, '\n')); err != nil {
			t.Fatal(err)
		}
		reader := bufio.NewReaderSize(outR, MaximumFrame+2)
		frame, err := ReadFrame(reader, MaximumFrame)
		if err != nil {
			t.Fatal(err)
		}
		var c generated.HostActionChallenge
		if err = json.Unmarshal(frame, &c); err != nil {
			t.Fatal(err)
		}
		digest, _ := BundleDigest(b)
		a := generated.HostActionAuthorization{Schema: generated.SchemaIDHostActionAuthorization, SchemaVersion: "1.0.0", BundleDigest: digest, ChallengeDigest: Digest(c), KeyID: p.KeyID, AuthorizedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(5 * time.Second).Format(time.RFC3339), StateRevision: b.StateRevision, RecoveryEpoch: b.RecoveryEpoch}
		a.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, AuthorizationMessage(a)))
		if err = WriteFrame(inW, a, MaximumFrame); err != nil {
			t.Fatal(err)
		}
		inW.Close()
		_, readErr := ReadFrame(reader, MaximumFrame)
		err = <-done
		outR.Close()
		if attempt == 0 && (err != nil || readErr != nil) {
			t.Fatalf("first execution: %v %v", err, readErr)
		}
		if attempt == 1 && err == nil {
			t.Fatal("replayed action")
		}
	}
}

func TestBlockedChallengeOutputIsCancelled(t *testing.T) {
	b, p, key, now := fixtureBundle(t)
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	receipts, err := OpenReceipts(root, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer receipts.Close()
	raw, _ := SignEnvelope(b, p.KeyID, key)
	outR, outW := io.Pipe()
	defer outR.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- RunOnce(ctx, bytes.NewReader(append(raw, '\n')), outW, p, receipts, testDispatcher{fileHandler{root + "/effect"}}, func() time.Time { return now }, rand.Reader)
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("blocked write succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("blocked output ignored cancellation")
	}
	if _, err := os.Stat(root + "/effect"); !os.IsNotExist(err) {
		t.Fatal("action ran after cancelled handshake")
	}
}
