package backup

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
)

type OneRunConfig struct {
	Issuer  adapter.SessionIssuer
	Parent  *credentialref.Value
	Request adapter.SessionRequest
	Bearer  []byte
	Path    string
	Clock   func() time.Time
}

// OneRunEndpoint is a loopback-only Minio IAM credential endpoint. It issues
// only while its exact child is alive and retains no session secret after the
// response is encoded.
type OneRunEndpoint struct {
	mu                  sync.Mutex
	config              OneRunConfig
	closed, childExited bool
	expiries            []time.Time
}

func NewOneRunEndpoint(config OneRunConfig) (*OneRunEndpoint, error) {
	if config.Issuer == nil || config.Parent == nil || len(config.Parent.Bytes()) == 0 || len(config.Bearer) < 32 ||
		config.Path == "" || config.Path[0] != '/' || config.Request.RunID == "" || config.Request.StepID == "" ||
		config.Request.GenerationID == "" || config.Request.PointID == "" || config.Request.Deadline.IsZero() {
		return nil, errors.New("invalid one-run endpoint")
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	config.Bearer = append([]byte(nil), config.Bearer...)
	return &OneRunEndpoint{config: config}, nil
}

func (endpoint *OneRunEndpoint) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	endpoint.mu.Lock()
	defer endpoint.mu.Unlock()
	deny := func() {
		writer.Header().Set("Cache-Control", "no-store")
		http.Error(writer, "denied", http.StatusForbidden)
	}
	if endpoint.closed || endpoint.childExited || request.Method != http.MethodGet || request.URL.Path != endpoint.config.Path ||
		!loopbackRemote(request.RemoteAddr) || !endpoint.config.Clock().Before(endpoint.config.Request.Deadline) {
		deny()
		return
	}
	got := []byte(request.Header.Get("Authorization"))
	want := append([]byte("Bearer "), endpoint.config.Bearer...)
	if len(got) != len(want) || subtle.ConstantTimeCompare(got, want) != 1 {
		deny()
		return
	}
	session, err := endpoint.config.Issuer.Issue(request.Context(), endpoint.config.Request, endpoint.config.Parent)
	if err != nil {
		deny()
		return
	}
	defer zeroScopedSession(&session)
	endpoint.expiries = append(endpoint.expiries, session.ExpiresAt.UTC())
	payload := struct {
		Code            string `json:"Code"`
		AccessKeyID     string `json:"AccessKeyId"`
		SecretAccessKey string `json:"SecretAccessKey"`
		Token           string `json:"Token"`
		Expiration      string `json:"Expiration"`
	}{"Success", string(session.AccessKeyID), string(session.SecretAccessKey), string(session.SessionToken), session.ExpiresAt.UTC().Format(time.RFC3339)}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	if json.NewEncoder(writer).Encode(payload) != nil {
		return
	}
}

func loopbackRemote(remote string) bool {
	host, port, err := net.SplitHostPort(remote)
	if err != nil || port == "" {
		return false
	}
	address := net.ParseIP(host)
	return address != nil && address.IsLoopback()
}

func (endpoint *OneRunEndpoint) MarkChildExited() {
	if endpoint == nil {
		return
	}
	endpoint.mu.Lock()
	endpoint.childExited = true
	endpoint.mu.Unlock()
}

func (endpoint *OneRunEndpoint) SessionExpiries() []time.Time {
	if endpoint == nil {
		return nil
	}
	endpoint.mu.Lock()
	defer endpoint.mu.Unlock()
	return append([]time.Time(nil), endpoint.expiries...)
}

func (endpoint *OneRunEndpoint) Close() error {
	if endpoint == nil {
		return nil
	}
	endpoint.mu.Lock()
	defer endpoint.mu.Unlock()
	endpoint.closed = true
	for index := range endpoint.config.Bearer {
		endpoint.config.Bearer[index] = 0
	}
	endpoint.config.Bearer = nil
	return nil
}

func zeroScopedSession(session *adapter.ScopedS3Session) {
	for _, value := range [][]byte{session.AccessKeyID, session.SecretAccessKey, session.SessionToken} {
		for index := range value {
			value[index] = 0
		}
	}
	session.AccessKeyID, session.SecretAccessKey, session.SessionToken = nil, nil, nil
}

func OneRunIAMPath(request adapter.SessionRequest) string {
	return "/v1/credentials/" + request.RunID + "/" + request.StepID + "/" + request.GenerationID + "/" + strconv.FormatInt(request.RecoveryEpoch, 10)
}
