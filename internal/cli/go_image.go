package cli

import (
	"context"
	"fmt"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/release"
)

func (app *App) buildGoImage(ctx context.Context, p parsedArguments) int {
	out, err := release.BuildGoImageFile(ctx, p.Value("--binary"), release.GoImageRequest{SourceURI: p.Value("--source-uri"), SourceRevision: p.Value("--source-revision"), BuilderID: p.Value("--builder-id"), InvocationID: p.Value("--invocation-id")})
	if err == nil {
		err = release.WriteGoImage(ctx, p.Value("--directory"), out)
	}
	if err != nil {
		code := generated.ErrorCodeEvidenceInvalid
		if ctx.Err() != nil {
			code = generated.ErrorCodeInterrupted
		}
		return app.fail(p.output, p.commandName(), code, "go-image", generated.RunStatusFailed, false)
	}
	data := generated.GoImageBuildData{Schema: generated.SchemaIDGoImageBuildData, SchemaVersion: "1.0.0", ImageDigest: out.Expected.ImageDigest, SignatureStatus: "unsigned", InventoryScope: "compiled-go-modules-only", ProvenanceScope: "binary-packaging-only", MetadataTrust: "caller-and-compiler-reported-unverified"}
	if p.output == outputJSON {
		return app.succeedData(p.commandName(), data)
	}
	if _, err = fmt.Fprintf(app.stdout, "Packaged image %s\nUnsigned statements; compiled Go-module inventory and binary packaging provenance only. Source and builder identities are caller/compiler-reported metadata. No signing or publication performed.\n", data.ImageDigest); err != nil {
		return exitCodeFor(generated.ErrorCodeIntegrityFailure)
	}
	return 0
}
