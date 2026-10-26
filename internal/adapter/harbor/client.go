// Package harbor implements the fixed read-only Harbor v2.14.6 artifact API.
// It supplies observations, never signature, provenance or workload qualification.
package harbor

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/failure"
)

const maxBody = 1 << 20
const requestTimeout = 10 * time.Second
const vulnerabilityReport = "application/vnd.security.vulnerability.report; version=1.1"

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var componentPattern = regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*$`)
var repositoryComponentPattern = regexp.MustCompile(`^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*$`)

// ArtifactTarget is supplied by trusted server composition, not a provider URL.
// Repository excludes Project; optional numeric IDs bind previously observed ownership.
type ArtifactTarget struct {
	Project      string
	Repository   string
	Digest       string
	ProjectID    int64
	RepositoryID int64
}

// ArtifactSnapshot contains only allowlisted observations. An index's digest is
// the index identity, not a claim about any selected child or running platform.
type ArtifactSnapshot struct {
	Project           string
	Repository        string
	Digest            string
	ProjectID         int64
	RepositoryID      int64
	Kind              string // image, index, or unknown
	ManifestMediaType string // empty for unknown provider media types
	ScanState         string // not-scanned, pending, running, error, unavailable, passed, findings
	Vulnerabilities   *int64
	SignatureState    string // always unverified
	ProvenanceState   string // always unverified
	PlatformVerified  bool   // always false: no child/platform verification is performed
	ObservedAt        time.Time
}

type Client struct {
	origin string
	http   *http.Client
}

func clientError(code string) error { return failure.New(code, "harbor-artifact", false) }

// NewClient accepts an HTTPS origin only. A supplied transport is trusted
// composition/test injection. The default has no environment proxy or redirects.
func NewClient(baseURL string, transport http.RoundTripper) (*Client, error) {
	u, e := url.Parse(baseURL)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.Hostname() == "" || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" || (u.Path != "" && u.Path != "/") || u.RawPath != "" || strings.ContainsAny(baseURL, "\\\r\n\t ") {
		return nil, clientError("INPUT_INVALID")
	}
	if port := u.Port(); port != "" {
		n, e := strconv.Atoi(port)
		if e != nil || n < 1 || n > 65535 {
			return nil, clientError("INPUT_INVALID")
		}
	}
	if transport == nil {
		transport = &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: requestTimeout}).DialContext, TLSHandshakeTimeout: requestTimeout, ResponseHeaderTimeout: requestTimeout, MaxResponseHeaderBytes: 32 << 10, DisableKeepAlives: true, DisableCompression: true}
	}
	return &Client{origin: "https://" + u.Host, http: &http.Client{Transport: transport, Timeout: requestTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func validTarget(t ArtifactTarget) bool {
	if len(t.Project) > 255 || !componentPattern.MatchString(t.Project) || len(t.Repository) > 255 || !digestPattern.MatchString(t.Digest) || t.ProjectID < 0 || t.RepositoryID < 0 {
		return false
	}
	for _, part := range strings.Split(t.Repository, "/") {
		if !repositoryComponentPattern.MatchString(part) {
			return false
		}
	}
	return true
}

// InspectArtifact makes exactly one GET, with no retry, mutation, tag resolution
// or auxiliary discovery. Credentials remain owned by the caller.
func (c *Client) InspectArtifact(ctx context.Context, target ArtifactTarget, username string, secret *credentialref.Value) (ArtifactSnapshot, error) {
	var zero ArtifactSnapshot
	if c == nil || c.http == nil || ctx == nil || !validTarget(target) || username == "" || len(username) > 256 || strings.ContainsAny(username, ":\r\n\x00") || len(secret.Bytes()) == 0 || bytes.ContainsAny(secret.Bytes(), "\r\n\x00") {
		return zero, clientError("INPUT_INVALID")
	}
	for _, r := range username {
		if r < 32 || r == 127 {
			return zero, clientError("INPUT_INVALID")
		}
	}
	bounded, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	// Harbor v2.14.6 parameters.repositoryName explicitly requires a/b -> a%252Fb.
	path := "/api/v2.0/projects/" + target.Project + "/repositories/" + url.PathEscape(url.PathEscape(target.Repository)) + "/artifacts/" + target.Digest + "?with_scan_overview=true"
	req, e := http.NewRequestWithContext(bounded, http.MethodGet, c.origin+path, nil)
	if e != nil {
		return zero, clientError("INPUT_INVALID")
	}
	req.SetBasicAuth(username, string(secret.Bytes()))
	req.Header.Set("Accept", "application/json")
	response, e := c.http.Do(req)
	if e != nil {
		return zero, clientError("DEPENDENCY_UNAVAILABLE")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		code := "DEPENDENCY_UNAVAILABLE"
		switch response.StatusCode {
		case 401:
			code = "AUTHENTICATION_REQUIRED"
		case 403:
			code = "AUTHORIZATION_DENIED"
		case 404:
			code = "RESOURCE_NOT_FOUND"
		case 429:
			code = "RATE_LIMITED"
		}
		return zero, clientError(code)
	}
	media, _, e := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if e != nil || media != "application/json" {
		return zero, clientError("INTEGRITY_FAILURE")
	}
	body, e := io.ReadAll(io.LimitReader(response.Body, maxBody+1))
	if e != nil || len(body) > maxBody || !validJSON(body) {
		return zero, clientError("INTEGRITY_FAILURE")
	}
	var wire struct {
		Digest            string                     `json:"digest"`
		ProjectID         *int64                     `json:"project_id"`
		RepositoryID      *int64                     `json:"repository_id"`
		ProjectName       *string                    `json:"project_name"`
		RepositoryName    *string                    `json:"repository_name"`
		ManifestMediaType string                     `json:"manifest_media_type"`
		ScanOverview      map[string]json.RawMessage `json:"scan_overview"`
	}
	if json.Unmarshal(body, &wire) != nil || wire.Digest != target.Digest ||
		(wire.ProjectName != nil && *wire.ProjectName != target.Project) ||
		(wire.RepositoryName != nil && *wire.RepositoryName != target.Project+"/"+target.Repository) ||
		(wire.ProjectID != nil && (*wire.ProjectID <= 0 || (target.ProjectID != 0 && *wire.ProjectID != target.ProjectID))) ||
		(wire.RepositoryID != nil && (*wire.RepositoryID <= 0 || (target.RepositoryID != 0 && *wire.RepositoryID != target.RepositoryID))) ||
		(target.ProjectID != 0 && wire.ProjectID == nil) || (target.RepositoryID != 0 && wire.RepositoryID == nil) {
		return zero, clientError("INTEGRITY_FAILURE")
	}
	out := ArtifactSnapshot{Project: target.Project, Repository: target.Repository, Digest: target.Digest, Kind: "unknown", SignatureState: "unverified", ProvenanceState: "unverified", ObservedAt: time.Now().UTC()}
	if wire.ProjectID != nil {
		out.ProjectID = *wire.ProjectID
	}
	if wire.RepositoryID != nil {
		out.RepositoryID = *wire.RepositoryID
	}
	switch wire.ManifestMediaType {
	case "application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json":
		out.Kind = "image"
		out.ManifestMediaType = wire.ManifestMediaType
	case "application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json":
		out.Kind = "index"
		out.ManifestMediaType = wire.ManifestMediaType
	}
	out.ScanState, out.Vulnerabilities = scanState(wire.ScanOverview)
	return out, nil
}

func scanState(overview map[string]json.RawMessage) (string, *int64) {
	if len(overview) == 0 {
		return "not-scanned", nil
	}
	// One known report format only. Unknown summaries are not scanner success.
	raw, ok := overview[vulnerabilityReport]
	if !ok || len(overview) != 1 {
		return "unavailable", nil
	}
	var report struct {
		Status  string `json:"scan_status"`
		Percent *int   `json:"complete_percent"`
		Summary *struct {
			Total *int64 `json:"total"`
		} `json:"summary"`
	}
	if json.Unmarshal(raw, &report) != nil {
		return "unavailable", nil
	}
	switch report.Status {
	case "Pending", "Scheduled":
		return "pending", nil
	case "Running":
		return "running", nil
	case "Error", "Stopped":
		return "error", nil
	case "Success":
		if report.Percent == nil || *report.Percent != 100 || report.Summary == nil || report.Summary.Total == nil || *report.Summary.Total < 0 {
			return "unavailable", nil
		}
		if *report.Summary.Total > 0 {
			return "findings", report.Summary.Total
		}
		return "passed", report.Summary.Total
	default:
		return "unavailable", nil
	}
}

// Validate every object, including ignored fields, before typed decoding:
// encoding/json otherwise accepts duplicate keys and case-folded field aliases.
func validJSON(body []byte) bool {
	d := json.NewDecoder(bytes.NewReader(body))
	d.UseNumber()
	first, e := d.Token()
	if e != nil || first != json.Delim('{') {
		return false
	}
	if !jsonContainer(d, json.Delim('{'), 0) {
		return false
	}
	_, e = d.Token()
	return e == io.EOF
}
func jsonContainer(d *json.Decoder, opening json.Delim, depth int) bool {
	if depth > 32 {
		return false
	}
	seen := map[string]bool{}
	for d.More() {
		if opening == '{' {
			k, e := d.Token()
			name, ok := k.(string)
			if e != nil || !ok {
				return false
			}
			folded := strings.ToLower(name)
			if seen[folded] {
				return false
			}
			seen[folded] = true
		}
		token, e := d.Token()
		if e != nil {
			return false
		}
		if delim, ok := token.(json.Delim); ok {
			if delim != '{' && delim != '[' {
				return false
			}
			if !jsonContainer(d, delim, depth+1) {
				return false
			}
		}
	}
	end, e := d.Token()
	return e == nil && ((opening == '{' && end == json.Delim('}')) || (opening == '[' && end == json.Delim(']')))
}
