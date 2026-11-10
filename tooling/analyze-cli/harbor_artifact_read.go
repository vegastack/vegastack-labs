package main

// #391 selects exact pull-robot artifact read; prior seals remain unchanged.
var harborArtifactReadSourceSeals = map[string]hostActionSourceSeal{
	"internal/adapter/harbor|client.go,lifecycle.go": {imports: []string{"bytes", "context", "encoding/json", "github.com/vegastack/vegastack-labs/internal/credentialref", "github.com/vegastack/vegastack-labs/internal/failure", "io", "mime", "net", "net/http", "net/url", "regexp", "sort", "strconv", "strings", "time", "unicode/utf8"}, digest: "3dfae0be1ff9b21a7129747aa50904430d4f8e5cccb941d52608c32299185971"},
}
