package main

// #391 adds only the reviewed Harbor source/import bytes; historical seals remain unchanged.
var harborRecoverySourceSeals = map[string]hostActionSourceSeal{
	"internal/adapter/harbor|client.go,lifecycle.go": {imports: []string{"bytes", "context", "encoding/json", "github.com/vegastack/vegastack-labs/internal/credentialref", "github.com/vegastack/vegastack-labs/internal/failure", "io", "mime", "net", "net/http", "net/url", "regexp", "sort", "strconv", "strings", "time", "unicode/utf8"}, digest: "e213e5f387829f50a22bab723b587558c26407e692d60b5f80415a31a4ab2391"},
}
