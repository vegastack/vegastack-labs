package r2

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter"
)

// LocalSigner implements Cloudflare R2's documented client-side temporary
// credential format. Parent material is an exact, borrowed JSON object and is
// never retained. The derived session is limited to one bucket, one generation
// prefix, the caller's exact action set, and the requested TTL.
type LocalSigner struct {
	Endpoint string
	Bucket   string
	Clock    func() time.Time
}

type parentCredential struct {
	AccountID       string `json:"accountId"`
	AccessKeyID     string `json:"accessKeyId"`
	SecretAccessKey string `json:"secretAccessKey"`
}

func (signer LocalSigner) SignScopedSession(ctx context.Context, parent []byte, request adapter.SessionRequest) (adapter.ScopedS3Session, error) {
	if err := ctx.Err(); err != nil {
		return adapter.ScopedS3Session{}, err
	}
	parsed, err := url.Parse(signer.Endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || signer.Bucket == "" || request.Prefix == "" || request.TTL <= 0 {
		return adapter.ScopedS3Session{}, errors.New("r2 local signing denied")
	}
	credential, err := decodeParentCredential(parent)
	if err != nil {
		return adapter.ScopedS3Session{}, errors.New("r2 parent credential invalid")
	}
	return signer.sign(credential, parsed.Host, request)
}

func decodeParentCredential(parent []byte) (parentCredential, error) {
	decoder := json.NewDecoder(bytes.NewReader(parent))
	decoder.DisallowUnknownFields()
	var credential parentCredential
	var trailing any
	if decoder.Decode(&credential) != nil || !errors.Is(decoder.Decode(&trailing), io.EOF) || credential.AccountID == "" || credential.AccessKeyID == "" || credential.SecretAccessKey == "" {
		return parentCredential{}, errors.New("r2 parent credential invalid")
	}
	return credential, nil
}

func parentS3Credentials(parent []byte) (S3Credentials, error) {
	credential, err := decodeParentCredential(parent)
	if err != nil {
		return S3Credentials{}, err
	}
	return S3Credentials{AccessKeyID: []byte(credential.AccessKeyID), SecretAccessKey: []byte(credential.SecretAccessKey)}, nil
}

func (signer LocalSigner) sign(credential parentCredential, audience string, request adapter.SessionRequest) (adapter.ScopedS3Session, error) {
	now := time.Now().UTC()
	if signer.Clock != nil {
		now = signer.Clock().UTC()
	}
	header, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	scope := "object-read-only"
	for _, action := range request.Actions {
		if action == "PutObject" || action == "DeleteObject" || action == "CreateMultipartUpload" || action == "UploadPart" || action == "CompleteMultipartUpload" || action == "AbortMultipartUpload" {
			scope = "object-read-write"
			break
		}
	}
	claims, err := json.Marshal(struct {
		Bucket    string              `json:"bucket"`
		Scope     string              `json:"scope"`
		Actions   []string            `json:"actions"`
		Paths     map[string][]string `json:"paths"`
		Subject   string              `json:"sub"`
		Issuer    string              `json:"iss"`
		Audience  string              `json:"aud"`
		IssuedAt  int64               `json:"iat"`
		ExpiresAt int64               `json:"exp"`
	}{signer.Bucket, scope, append([]string(nil), request.Actions...), map[string][]string{"prefixPaths": {request.Prefix}, "objectPaths": {}}, credential.AccountID, credential.AccessKeyID, audience, now.Unix(), now.Add(request.TTL).Unix()})
	if err != nil {
		return adapter.ScopedS3Session{}, err
	}
	encode := base64.RawURLEncoding.EncodeToString
	unsigned := encode(header) + "." + encode(claims)
	mac := hmac.New(sha256.New, []byte(credential.SecretAccessKey))
	_, _ = mac.Write([]byte(unsigned))
	jwt := unsigned + "." + encode(mac.Sum(nil))
	secret := sha256.Sum256([]byte(jwt))
	token := base64.StdEncoding.EncodeToString([]byte("jwt/" + jwt))
	return adapter.ScopedS3Session{AccessKeyID: []byte(credential.AccessKeyID), SecretAccessKey: []byte(hex.EncodeToString(secret[:])), SessionToken: []byte(token), ExpiresAt: now.Add(request.TTL)}, nil
}

var _ TemporaryCredentialSigner = LocalSigner{}
