package store

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"strings"
	"testing"
	"time"
)

func bindingFixture() generated.BrowserIdentityBindingChange {
	return generated.BrowserIdentityBindingChange{Schema: generated.SchemaIDBrowserIdentityBindingChange, SchemaVersion: "1.0.0", Action: "bind", Method: identity.CloudflareAccessMethod, Issuer: "https://synthetic.cloudflareaccess.com", Subject: "subject-human", Audiences: []string{"aud-a", "aud-b"}}
}
func TestBrowserIdentityBindingMetadataDigestAndBounds(t *testing.T) {
	b := bindingFixture()
	digest, err := BrowserIdentityBindingDigest(b)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := identity.BindingDigest(identity.VerifiedIdentity{Method: b.Method, Issuer: b.Issuer, Subject: b.Subject, Audiences: []string{"aud-b", "aud-a"}, IssuedAt: time.Unix(10, 0), ExpiresAt: time.Unix(20, 0)})
	if err != nil || expected != digest {
		t.Fatal("binding digest diverged", digest, expected, err)
	}
	for _, mutate := range []func(*generated.BrowserIdentityBindingChange){func(b *generated.BrowserIdentityBindingChange) { b.Audiences = []string{"b", "a"} }, func(b *generated.BrowserIdentityBindingChange) { b.Subject = " contains space" }, func(b *generated.BrowserIdentityBindingChange) { b.Issuer = strings.Repeat("a", 2049) }, func(b *generated.BrowserIdentityBindingChange) { b.Audiences = []string{strings.Repeat("a", 513)} }, func(b *generated.BrowserIdentityBindingChange) { b.Method = "slack-socket-mode" }, func(b *generated.BrowserIdentityBindingChange) { b.Audiences = []string{"a", "a"} }} {
		v := bindingFixture()
		mutate(&v)
		if _, e := BrowserIdentityBindingDigest(v); e == nil {
			t.Fatal("invalid metadata accepted")
		}
	}
	in := lifecycleFixture("")
	in.IdentityBinding = &b
	if err := ValidateAuthorizationGrantBatch(in); err != nil {
		t.Fatal(err)
	}
	in.LifecycleAction = "suspend"
	if ValidateAuthorizationGrantBatch(in) == nil {
		t.Fatal("mixed user/binding accepted")
	}
	in.LifecycleAction = ""
	in.ExpectedGrantRevision = 0
	if ValidateAuthorizationGrantBatch(in) == nil {
		t.Fatal("absent principal revision accepted")
	}
}

func TestBrowserIdentityBindingRejectsMixedDeviceAction(t *testing.T) {
	binding := bindingFixture()
	in := lifecycleFixture("")
	in.IdentityBinding = &binding
	for _, field := range []string{"action", "id", "revision"} {
		v := in
		switch field {
		case "action":
			v.DeviceAction = "request"
			v.DeviceID = "synthetic-device"
		case "id":
			v.DeviceID = "synthetic-device"
		case "revision":
			v.ExpectedDeviceRevision = 1
		}
		if ValidateAuthorizationGrantBatch(v) == nil {
			t.Fatal("binding mixed with device field accepted", field)
		}
	}
}
