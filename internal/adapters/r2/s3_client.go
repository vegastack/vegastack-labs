package r2

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/backup"
)

type S3Credentials struct {
	AccessKeyID, SecretAccessKey, SessionToken string
}

// S3Client is the narrow R2 data-plane client used by the qualified observer.
// It implements only exact generation listing/full reads and cutoff probes.
type S3Client struct {
	Endpoint string
	Bucket   string
	Client   *http.Client
	Clock    func() time.Time
}

func (client S3Client) Inventory(ctx context.Context, prefix string, credentials S3Credentials, maximumObjects, maximumBytes int64) (backup.OffsiteInventoryObservation, error) {
	if maximumObjects < 1 || maximumBytes < 1 || prefix == "" {
		return backup.OffsiteInventoryObservation{}, errors.New("r2 inventory bounds invalid")
	}
	objects := []backup.OffsiteObject{}
	continuation := ""
	var bytesRead int64
	for {
		query := url.Values{"list-type": {"2"}, "prefix": {strings.TrimSuffix(prefix, "/") + "/"}}
		if continuation != "" {
			query.Set("continuation-token", continuation)
		}
		response, err := client.do(ctx, http.MethodGet, "/"+client.Bucket, query, nil, credentials)
		if err != nil {
			return backup.OffsiteInventoryObservation{}, err
		}
		var listing struct {
			IsTruncated           bool   `xml:"IsTruncated"`
			NextContinuationToken string `xml:"NextContinuationToken"`
			Contents              []struct {
				Key  string `xml:"Key"`
				Size int64  `xml:"Size"`
			} `xml:"Contents"`
		}
		if response.StatusCode != http.StatusOK || xml.NewDecoder(io.LimitReader(response.Body, 4<<20)).Decode(&listing) != nil || response.Body.Close() != nil {
			return backup.OffsiteInventoryObservation{}, errors.New("r2 inventory listing failed")
		}
		generationPrefix := strings.TrimSuffix(prefix, "/") + "/"
		for _, listed := range listing.Contents {
			if int64(len(objects)) >= maximumObjects || listed.Size < 0 || bytesRead > maximumBytes-listed.Size {
				return backup.OffsiteInventoryObservation{}, errors.New("r2 inventory exceeds bounds")
			}
			if !strings.HasPrefix(listed.Key, generationPrefix) {
				return backup.OffsiteInventoryObservation{}, errors.New("r2 inventory returned object outside generation")
			}
			relative := strings.TrimPrefix(listed.Key, generationPrefix)
			if relative == "" || strings.HasPrefix(relative, "/") || path.Clean(relative) != relative || strings.Contains(relative, "\\") {
				return backup.OffsiteInventoryObservation{}, errors.New("r2 inventory object key invalid")
			}
			objectResponse, getErr := client.do(ctx, http.MethodGet, "/"+client.Bucket+"/"+escapeS3Key(listed.Key), nil, nil, credentials)
			if getErr != nil || objectResponse.StatusCode != http.StatusOK {
				if objectResponse != nil {
					_ = objectResponse.Body.Close()
				}
				return backup.OffsiteInventoryObservation{}, errors.New("r2 inventory full read failed")
			}
			hasher := sha256.New()
			read, copyErr := io.CopyN(hasher, objectResponse.Body, listed.Size+1)
			closeErr := objectResponse.Body.Close()
			if copyErr != nil && !errors.Is(copyErr, io.EOF) || closeErr != nil || read != listed.Size {
				return backup.OffsiteInventoryObservation{}, errors.New("r2 inventory object size mismatch")
			}
			objects = append(objects, backup.OffsiteObject{Key: relative, Digest: "sha256:" + hex.EncodeToString(hasher.Sum(nil)), Bytes: listed.Size})
			bytesRead += listed.Size
		}
		if !listing.IsTruncated {
			break
		}
		if listing.NextContinuationToken == "" || listing.NextContinuationToken == continuation {
			return backup.OffsiteInventoryObservation{}, errors.New("r2 inventory pagination invalid")
		}
		continuation = listing.NextContinuationToken
	}
	sort.Slice(objects, func(i, j int) bool { return objects[i].Key < objects[j].Key })
	for index := 1; index < len(objects); index++ {
		if objects[index-1].Key == objects[index].Key {
			return backup.OffsiteInventoryObservation{}, errors.New("r2 inventory contains duplicate object")
		}
	}
	return backup.OffsiteInventoryObservation{InventoryDigest: backup.DigestOffsiteInventory(objects), ObjectCount: int64(len(objects)), ObjectBytes: bytesRead, Objects: objects}, nil
}

func (client S3Client) ProbePutDenied(ctx context.Context, key string, credentials S3Credentials) (bool, error) {
	response, err := client.do(ctx, http.MethodPut, "/"+client.Bucket+"/"+escapeS3Key(key), nil, []byte("cutoff-probe"), credentials)
	if err != nil {
		return false, err
	}
	defer response.Body.Close()
	return response.StatusCode == http.StatusForbidden, nil
}

func (client S3Client) InitiateMultipart(ctx context.Context, key string, credentials S3Credentials) (string, error) {
	response, err := client.do(ctx, http.MethodPost, "/"+client.Bucket+"/"+escapeS3Key(key), url.Values{"uploads": {""}}, nil, credentials)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	var result struct {
		UploadID string `xml:"UploadId"`
	}
	if response.StatusCode != http.StatusOK || xml.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&result) != nil || result.UploadID == "" {
		return "", errors.New("r2 multipart probe initiation failed")
	}
	return result.UploadID, nil
}

func (client S3Client) ProbeMultipartCompletionDenied(ctx context.Context, key, uploadID string, credentials S3Credentials) (bool, error) {
	body := []byte(`<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>"cutoff"</ETag></Part></CompleteMultipartUpload>`)
	response, err := client.do(ctx, http.MethodPost, "/"+client.Bucket+"/"+escapeS3Key(key), url.Values{"uploadId": {uploadID}}, body, credentials)
	if err != nil {
		return false, err
	}
	defer response.Body.Close()
	return response.StatusCode == http.StatusForbidden, nil
}

func (client S3Client) DeleteObject(ctx context.Context, key string, credentials S3Credentials) error {
	response, err := client.do(ctx, http.MethodDelete, "/"+client.Bucket+"/"+escapeS3Key(key), nil, nil, credentials)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent && response.StatusCode != http.StatusOK && response.StatusCode != http.StatusNotFound {
		return errors.New("r2 cutoff object cleanup failed")
	}
	return nil
}

func (client S3Client) AbortMultipart(ctx context.Context, key, uploadID string, credentials S3Credentials) error {
	response, err := client.do(ctx, http.MethodDelete, "/"+client.Bucket+"/"+escapeS3Key(key), url.Values{"uploadId": {uploadID}}, nil, credentials)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent && response.StatusCode != http.StatusOK && response.StatusCode != http.StatusNotFound {
		return errors.New("r2 cutoff multipart cleanup failed")
	}
	return nil
}

func (client S3Client) do(ctx context.Context, method, objectPath string, query url.Values, body []byte, credentials S3Credentials) (*http.Response, error) {
	base, err := url.Parse(client.Endpoint)
	if err != nil || base.Host == "" || base.Path != "" || credentials.AccessKeyID == "" || credentials.SecretAccessKey == "" {
		return nil, errors.New("r2 s3 client unavailable")
	}
	base.Path = objectPath
	base.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, method, base.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	if client.Clock != nil {
		now = client.Clock().UTC()
	}
	payload := sha256.Sum256(body)
	payloadHex := hex.EncodeToString(payload[:])
	request.Header.Set("x-amz-content-sha256", payloadHex)
	request.Header.Set("x-amz-date", now.Format("20060102T150405Z"))
	if credentials.SessionToken != "" {
		request.Header.Set("x-amz-security-token", credentials.SessionToken)
	}
	signedHeaders := []string{"host", "x-amz-content-sha256", "x-amz-date"}
	if credentials.SessionToken != "" {
		signedHeaders = append(signedHeaders, "x-amz-security-token")
	}
	canonicalHeaders := "host:" + request.URL.Host + "\n" + "x-amz-content-sha256:" + payloadHex + "\n" + "x-amz-date:" + request.Header.Get("x-amz-date") + "\n"
	if credentials.SessionToken != "" {
		canonicalHeaders += "x-amz-security-token:" + credentials.SessionToken + "\n"
	}
	canonicalRequest := strings.Join([]string{method, request.URL.EscapedPath(), request.URL.Query().Encode(), canonicalHeaders, strings.Join(signedHeaders, ";"), payloadHex}, "\n")
	canonicalHash := sha256.Sum256([]byte(canonicalRequest))
	date := now.Format("20060102")
	scope := date + "/auto/s3/aws4_request"
	stringToSign := "AWS4-HMAC-SHA256\n" + request.Header.Get("x-amz-date") + "\n" + scope + "\n" + hex.EncodeToString(canonicalHash[:])
	dateKey := hmacSum([]byte("AWS4"+credentials.SecretAccessKey), date)
	regionKey := hmacSum(dateKey, "auto")
	serviceKey := hmacSum(regionKey, "s3")
	signingKey := hmacSum(serviceKey, "aws4_request")
	signature := hex.EncodeToString(hmacSum(signingKey, stringToSign))
	request.Header.Set("Authorization", fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s", credentials.AccessKeyID, scope, strings.Join(signedHeaders, ";"), signature))
	httpClient := client.Client
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return httpClient.Do(request)
}

func hmacSum(key []byte, value string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(value))
	return mac.Sum(nil)
}

func escapeS3Key(key string) string {
	parts := strings.Split(path.Clean(key), "/")
	for index := range parts {
		parts[index] = url.PathEscape(parts[index])
	}
	return strings.Join(parts, "/")
}

func sessionCredentials(session adapter.ScopedS3Session) S3Credentials {
	return S3Credentials{AccessKeyID: string(session.AccessKeyID), SecretAccessKey: string(session.SecretAccessKey), SessionToken: string(session.SessionToken)}
}
