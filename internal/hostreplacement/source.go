package hostreplacement

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
)

// ReplacementRestoreSource is produced by the server's actual recovery source
// verifier and snapshot reader. A source revision is not an alias watermark.
type ReplacementRestoreSource struct {
	Binding            generated.RestoreSourceBinding
	DatabaseDigest     string
	AliasHighWatermark int64
}
type ReplacementSourceVerifier interface {
	VerifyReplacementSource(context.Context, generated.HostReplacementSourceReference) (ReplacementRestoreSource, error)
}

func ResolveRestore(ctx context.Context, in generated.HostReplacementRequest, verifier ReplacementSourceVerifier) (ReplacementRestoreSource, error) {
	if ctx == nil || ctx.Err() != nil || ValidateInput(in) != nil || in.RestorationClass != "control-database" || in.Source == nil || verifier == nil {
		return ReplacementRestoreSource{}, errInput
	}
	source, err := verifier.VerifyReplacementSource(ctx, *in.Source)
	if err != nil {
		return ReplacementRestoreSource{}, err
	}
	if source.Binding.PointID != in.Source.PointID || source.Binding.ManifestDigest != in.Source.ManifestDigest || hostaction.Digest(source.Binding) != in.Source.SourceBindingDigest || source.DatabaseDigest == "" || source.AliasHighWatermark < 0 {
		return ReplacementRestoreSource{}, errInput
	}
	return source, nil
}
