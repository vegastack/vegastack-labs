package backup

import (
	"context"
	"errors"
	"net"
	"net/url"
	"strings"
)

// CopyOffsitePoint delegates the pinned S3 child to the custody broker. It
// returns pending evidence only; verification and last-good advancement are
// separate operations.
func CopyOffsitePoint(ctx context.Context, config CopyConfig, point VerifiedCriticalPoint, admission GenerationAdmission) (PendingOffsiteGeneration, error) {
	invalid := errors.New("offsite copy blocked")
	if config.Custody == nil || config.Inventory == nil || config.Endpoint == nil || config.Password == nil || len(config.Password.Bytes()) == 0 || config.BinaryPath == "" || config.Architecture == "" ||
		!offsiteRepositoryMatchesAdmission(config.RepositoryURL, config.Bucket, admission.Prefix) || config.SnapshotPath == "" || config.PasswordFDPath == "" ||
		config.AuthorizationTokenFDPath == "" || !validLoopbackIAMURI(config.IAMURI, config.Endpoint.config.Path) || point.PointID == "" || point.SnapshotID == "" ||
		admission.GenerationID != config.Binding.GenerationID || admission.GenerationID == "" ||
		config.Binding.PointID != point.PointID || config.Binding.RecoveryEpoch != point.RecoveryEpoch ||
		config.Endpoint.config.Path != OneRunIAMPath(config.Binding) {
		return PendingOffsiteGeneration{}, invalid
	}
	request := OffsiteResticRequest{BinaryPath: config.BinaryPath, Architecture: config.Architecture, RepositoryURL: config.RepositoryURL,
		SnapshotPath: config.SnapshotPath, ExpectedSnapshotID: point.SnapshotID, PasswordFDPath: config.PasswordFDPath,
		IAMURI: config.IAMURI, AuthorizationTokenFDPath: config.AuthorizationTokenFDPath,
		RunID: config.Binding.RunID, StepID: config.Binding.StepID, PointID: point.PointID, GenerationID: admission.GenerationID, RecoveryEpoch: point.RecoveryEpoch}
	request.Arguments = []string{config.BinaryPath, "-r", config.RepositoryURL, "--json", "--no-cache", "--password-file", config.PasswordFDPath, "backup", config.SnapshotPath, "--host", "vsk-labs"}
	request.Environment = []string{"HOME=/nonexistent", "RESTIC_PASSWORD_FILE=" + config.PasswordFDPath,
		"AWS_CONTAINER_CREDENTIALS_FULL_URI=" + config.IAMURI, "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE=" + config.AuthorizationTokenFDPath}
	result, err := config.Custody.RunOffsiteRestic(ctx, request, config.Password, config.Endpoint.config.Bearer)
	config.Endpoint.MarkChildExited()
	if err != nil {
		return PendingOffsiteGeneration{}, err
	}
	if !result.ChildExited || !validObjectName(result.RepositoryID) || !validObjectName(result.SnapshotID) || result.ObjectCount < 1 || result.ObjectBytes < 1 {
		return PendingOffsiteGeneration{}, invalid
	}
	expiries := config.Endpoint.SessionExpiries()
	if len(expiries) == 0 {
		return PendingOffsiteGeneration{}, invalid
	}
	observed, err := config.Inventory.ObserveOffsiteGeneration(ctx, admission.GenerationID, result.RepositoryID, result.SnapshotID)
	if err != nil || !validBackupManifestDigest(observed.InventoryDigest) || observed.ObjectCount < 1 || observed.ObjectBytes < 1 ||
		observed.ObjectBytes > admission.MaximumBytes || observed.ObjectCount > admission.MaximumPUTs {
		return PendingOffsiteGeneration{}, invalid
	}
	return PendingOffsiteGeneration{SourcePointID: point.PointID, SourceSnapshotID: point.SnapshotID, SourceManifestDigest: point.ManifestDigest,
		SourceInventoryDigest: point.InventoryDigest, SourceContentDigest: point.ContentDigest, SourceDependencyDigest: point.DependencyDigest,
		SourceResticDigest: point.ResticDigest, KeyReferenceID: point.KeyReferenceID, SourceRevision: point.SourceRevision, RecoveryEpoch: point.RecoveryEpoch,
		GenerationID: admission.GenerationID, RepositoryID: result.RepositoryID,
		OffsiteSnapshotID: result.SnapshotID, OffsiteInventoryDigest: observed.InventoryDigest,
		RuleDigest: admission.RuleDigest, SessionExpiries: expiries, ObjectCount: observed.ObjectCount, ObjectBytes: observed.ObjectBytes,
		IssuanceStoppedAt: config.Endpoint.ChildExitedAt()}, nil
}

func validLoopbackIAMURI(raw, expectedPath string) bool {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "http" || parsed.Path != expectedPath || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.User != nil {
		return false
	}
	host, port, err := net.SplitHostPort(parsed.Host)
	if err != nil || port == "" {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func validOffsiteRepositoryURL(raw string) bool {
	if !strings.HasPrefix(raw, "s3:") {
		return false
	}
	parsed, err := url.Parse(strings.TrimPrefix(raw, "s3:"))
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == ""
}

func offsiteRepositoryMatchesAdmission(raw, bucket, prefix string) bool {
	if !validOffsiteRepositoryURL(raw) || bucket == "" || strings.Contains(bucket, "/") || prefix == "" {
		return false
	}
	parsed, err := url.Parse(strings.TrimPrefix(raw, "s3:"))
	if err != nil || parsed.RawPath != "" {
		return false
	}
	wantPath := "/" + bucket + "/" + strings.TrimSuffix(prefix, "/")
	return parsed.Path == wantPath
}
