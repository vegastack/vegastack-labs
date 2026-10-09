package hostreplacement

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"testing"
)

type sourceFixture struct{ source ReplacementRestoreSource }

func (s sourceFixture) VerifyReplacementSource(context.Context, generated.HostReplacementSourceReference) (ReplacementRestoreSource, error) {
	return s.source, nil
}
func TestReplacementSourceRejectsDifferentVerifiedPoint(t *testing.T) {
	in, b := restoreFixture()
	source := ReplacementRestoreSource{Binding: b.Source, DatabaseDigest: hostaction.BytesDigest([]byte("database")), AliasHighWatermark: 7}
	got, e := ResolveRestore(context.Background(), in, sourceFixture{source})
	if e != nil || got.AliasHighWatermark != 7 {
		t.Fatalf("%+v %v", got, e)
	}
	source.Binding.PointID = "another"
	if _, e = ResolveRestore(context.Background(), in, sourceFixture{source}); e == nil {
		t.Fatal("different snapshot accepted")
	}
	if _, e = ResolveRestore(context.Background(), in, nil); e == nil {
		t.Fatal("missing real verifier accepted")
	}
}
