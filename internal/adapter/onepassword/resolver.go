package onepassword

import (
	"context"
	"errors"
	"slices"
	"time"

	sdk "github.com/1password/onepassword-sdk-go"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

type SecretsAPI interface {
	Resolve(context.Context, string) (string, error)
}

// Config belongs to the optional 1Password adapter/deployment profile, not
// platform-core metadata. A compatible policy must register it explicitly.
type Config struct {
	IDs                                                                       IDs
	ReferenceID, ConsumerID, PurposeID, TargetID, MaterialVersion, ResolverID string
	AllowedVaultIDs                                                           []string
}

type Resolver struct {
	config Config
	api    SecretsAPI
}

func sdkError(code, target string) error { return failure.New(code, target, false) }

func NewResolver(ctx context.Context, token *credentialref.Value, config Config, api SecretsAPI) (*Resolver, error) {
	if token != nil {
		defer token.Close()
	}
	if ctx == nil || token == nil || len(token.Bytes()) < 8 || len(token.Bytes()) > 4096 {
		return nil, sdkError(generated.ErrorCodePrerequisiteBlocked, "onepassword-token")
	}
	ids, err := ParseIDs(config.IDs.VaultID, config.IDs.ItemID, config.IDs.FieldID)
	if err != nil {
		return nil, err
	}
	config.IDs = ids
	for _, id := range []string{config.ReferenceID, config.ConsumerID, config.PurposeID, config.TargetID, config.MaterialVersion, config.ResolverID} {
		if _, err := credentialref.ParseID(id); err != nil {
			return nil, sdkError(generated.ErrorCodeInputInvalid, "onepassword-binding")
		}
	}
	if !slices.Contains(config.AllowedVaultIDs, ids.VaultID) || len(config.AllowedVaultIDs) == 0 {
		return nil, sdkError(generated.ErrorCodeAuthorizationDenied, "onepassword-vault")
	}
	for _, vaultID := range config.AllowedVaultIDs {
		if _, err := ParseIDs(vaultID, ids.ItemID, ids.FieldID); err != nil {
			return nil, sdkError(generated.ErrorCodeInputInvalid, "onepassword-vault-policy")
		}
	}
	if api == nil {
		// Only the server process holds the service-account token. The SDK owns
		// an immutable Go string after this call; application buffers are wiped
		// above and SDK memory is reclaimed only by Go GC.
		client, sdkErr := sdk.NewClient(ctx, sdk.WithServiceAccountToken(string(token.Bytes())), sdk.WithIntegrationInfo("vsk-labs", "1.0.0"))
		if sdkErr != nil {
			return nil, sdkError(generated.ErrorCodeDependencyUnavailable, "onepassword-client")
		}
		api = client.Secrets()
	}
	return &Resolver{config: config, api: api}, nil
}

func (resolver *Resolver) Resolve(ctx context.Context, binding credentialref.StepBinding) (*credentialref.Value, error) {
	if resolver == nil || resolver.api == nil || ctx == nil || !credentialref.ValidBinding(binding) {
		return nil, sdkError(generated.ErrorCodePrerequisiteBlocked, "onepassword-binding")
	}
	config := resolver.config
	if binding.ReferenceID != config.ReferenceID || binding.ConsumerID != config.ConsumerID || binding.PurposeID != config.PurposeID || binding.TargetID != config.TargetID || binding.MaterialVersion != config.MaterialVersion || binding.ResolverID != config.ResolverID || binding.AdapterID != config.ConsumerID || !slices.Contains(config.AllowedVaultIDs, config.IDs.VaultID) {
		return nil, sdkError(generated.ErrorCodeAuthorizationDenied, "onepassword-binding")
	}
	deadline, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	// One immutable reference only: no list, query, label fallback or second read.
	secret, err := resolver.api.Resolve(deadline, config.IDs.URI())
	if err != nil {
		var rateLimit *sdk.RateLimitExceededError
		if errors.As(err, &rateLimit) {
			return nil, failure.New(generated.ErrorCodeRateLimited, "onepassword-read", true)
		}
		return nil, sdkError(generated.ErrorCodeDependencyUnavailable, "onepassword-read")
	}
	if len(secret) == 0 || len(secret) > 4096 {
		return nil, sdkError(generated.ErrorCodeIntegrityFailure, "onepassword-value")
	}
	raw := []byte(secret)
	defer wipe(raw)
	value, err := credentialref.NewValue(raw)
	if err != nil {
		return nil, sdkError(generated.ErrorCodeIntegrityFailure, "onepassword-value")
	}
	if deadline.Err() != nil {
		value.Close()
		return nil, sdkError(generated.ErrorCodeInterrupted, "onepassword-read")
	}
	return value, nil
}

func wipe(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
