package main

// #391 corrects only vendor-omitted empty retention parameters; prior seals remain unchanged.
var harborRetentionSourceSeals = map[string]hostActionSourceSeal{
	"internal/adapter/harbor|client.go,lifecycle.go": {imports: []string{"bytes", "context", "encoding/json", "github.com/vegastack/vegastack-labs/internal/credentialref", "github.com/vegastack/vegastack-labs/internal/failure", "io", "mime", "net", "net/http", "net/url", "regexp", "sort", "strconv", "strings", "time", "unicode/utf8"}, digest: "3ff1879747b38a308e70d2c06c87ecce539c17d085c4dc2399494ee0168dfb8d"},
}
