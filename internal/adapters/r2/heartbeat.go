package r2

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/siteheartbeat"
)

const HeartbeatConsumer = "site-heartbeat-write"

var heartbeatBucketPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)

type HeartbeatResolver interface {
	credentialref.Inspector
	Resolve(context.Context, credentialref.Reference) (*credentialref.Value, error)
}

// HeartbeatWriter only PUTs one declared object. The protected reference must
// resolve provider-issued, narrow status-bucket credentials; their actual
// write-only grant and separation from backups remain deployment evidence.
type HeartbeatWriter struct {
	Client       S3Client
	ObjectKey    string
	BackupBucket string
	SiteDigest   string
	Reference    credentialref.Reference
	Resolver     HeartbeatResolver
}

func (w HeartbeatWriter) WriteHeartbeat(ctx context.Context, payload []byte) error {
	denied := errors.New("site heartbeat R2 write unavailable")
	endpoint, err := url.Parse(w.Client.Endpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.Path != "" || endpoint.Port() != "" || !strings.HasSuffix(endpoint.Hostname(), ".r2.cloudflarestorage.com") || !heartbeatBucketPattern.MatchString(w.Client.Bucket) || w.Client.Bucket == w.BackupBucket || w.ObjectKey != "heartbeat.json" || len(payload) > siteheartbeat.MaximumBytes {
		return denied
	}
	var heartbeat siteheartbeat.Heartbeat
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var trailing any
	if decoder.Decode(&heartbeat) != nil || !errors.Is(decoder.Decode(&trailing), io.EOF) || heartbeat.Schema != siteheartbeat.Schema || heartbeat.SchemaVersion != siteheartbeat.SchemaVersion || heartbeat.SiteDigest != w.SiteDigest {
		return denied
	}
	observed, err := time.Parse(time.RFC3339, heartbeat.ObservedAt)
	if err != nil {
		return denied
	}
	now := time.Now().UTC()
	if w.Client.Clock != nil {
		now = w.Client.Clock().UTC()
	}
	checked, err := siteheartbeat.Encode(siteheartbeat.Snapshot{SiteDigest: heartbeat.SiteDigest, ObservedAt: observed, StateRevision: heartbeat.StateRevision, RecoveryEpoch: heartbeat.RecoveryEpoch}, now)
	if err != nil || !bytes.Equal(payload, checked) {
		return denied
	}
	if _, err = credentialref.Verify(ctx, w.Resolver, w.Reference, HeartbeatConsumer); err != nil {
		return denied
	}
	value, err := w.Resolver.Resolve(ctx, w.Reference)
	if value != nil {
		defer value.Close()
	}
	if err != nil || value == nil {
		return denied
	}
	var material struct {
		AccessKeyID     string `json:"accessKeyId"`
		SecretAccessKey string `json:"secretAccessKey"`
		SessionToken    string `json:"sessionToken"`
	}
	decoder = json.NewDecoder(bytes.NewReader(value.Bytes()))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&material) != nil || !errors.Is(decoder.Decode(&trailing), io.EOF) || material.AccessKeyID == "" || material.SecretAccessKey == "" || material.SessionToken == "" {
		return denied
	}
	credentials := S3Credentials{AccessKeyID: []byte(material.AccessKeyID), SecretAccessKey: []byte(material.SecretAccessKey), SessionToken: []byte(material.SessionToken)}
	defer zeroS3Credentials(&credentials)
	client := w.Client
	httpClient := http.Client{Timeout: 5 * time.Second}
	if client.Client != nil {
		httpClient = *client.Client
		httpClient.Timeout = 5 * time.Second
	}
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	client.Client = &httpClient
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	response, err := client.do(ctx, http.MethodPut, "/"+client.Bucket+"/"+w.ObjectKey, nil, payload, credentials)
	if err != nil {
		return denied
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return denied
	}
	return nil
}
