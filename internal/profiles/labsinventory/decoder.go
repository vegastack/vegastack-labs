package labsinventory

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"io"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/vegastack/vegastack-labs/internal/inventory"
)

var utf8BOM = []byte{0xef, 0xbb, 0xbf}

// Decoder is an offline decoder for one immutable Labs Sheet1 CSV snapshot.
type Decoder struct {
	config Config
}

// NewDecoder validates trusted source metadata without consulting the source
// path, filesystem metadata, a provider, or the network.
func NewDecoder(config Config) (*Decoder, error) {
	_, offset := config.CapturedAt.Zone()
	if strings.TrimSpace(config.SourceRevision) == "" || len(config.SourceRevision) > inventory.MaxTokenBytes || !utf8.ValidString(config.SourceRevision) || config.CapturedAt.IsZero() || offset != 0 {
		return nil, decodeError(ErrorCSVMalformed, 0, 0, "source")
	}
	config.CapturedAt = config.CapturedAt.UTC()
	return &Decoder{config: config}, nil
}

// Decode reads, validates, and maps one strict bounded CSV snapshot. Returned
// candidates are inert and have no persistence or authority transition.
func (decoder *Decoder) Decode(ctx context.Context, source io.Reader) (inventory.DecodedCandidate, error) {
	if decoder == nil || source == nil {
		return inventory.DecodedCandidate{}, decodeError(ErrorCSVMalformed, 0, 0, "source")
	}
	raw, err := readBounded(ctx, source)
	if err != nil {
		return inventory.DecodedCandidate{}, err
	}
	if len(raw) == 0 {
		return inventory.DecodedCandidate{}, decodeError(ErrorCSVEmpty, 0, 0, "")
	}
	if !utf8.Valid(raw) {
		return inventory.DecodedCandidate{}, decodeError(ErrorCSVUTF8Invalid, 0, 0, "")
	}
	parseBytes := raw
	if bytes.HasPrefix(parseBytes, utf8BOM) {
		parseBytes = parseBytes[len(utf8BOM):]
	}
	if bytes.Contains(parseBytes, utf8BOM) {
		return inventory.DecodedCandidate{}, decodeError(ErrorCSVControlProhibited, 0, 0, "")
	}
	records, err := parseCSV(ctx, parseBytes)
	if err != nil {
		return inventory.DecodedCandidate{}, err
	}
	for recordIndex, record := range records {
		if recordIndex > 0 && len(record) != len(headerV1) {
			return inventory.DecodedCandidate{}, decodeError(ErrorCSVMalformed, recordIndex+1, 0, "")
		}
		for columnIndex, cell := range record {
			if len(cell) > MaxFieldBytes {
				return inventory.DecodedCandidate{}, decodeError(ErrorCSVLimitExceeded, recordIndex+1, columnIndex+1, fieldFor(columnIndex))
			}
			if formulaProhibited(cell) {
				return inventory.DecodedCandidate{}, decodeError(ErrorCSVFormulaProhibited, recordIndex+1, columnIndex+1, fieldFor(columnIndex))
			}
			if controlProhibited(cell) {
				return inventory.DecodedCandidate{}, decodeError(ErrorCSVControlProhibited, recordIndex+1, columnIndex+1, fieldFor(columnIndex))
			}
			if privateDataProhibited(cell) {
				return inventory.DecodedCandidate{}, decodeError(ErrorCSVControlProhibited, recordIndex+1, columnIndex+1, fieldFor(columnIndex))
			}
		}
	}
	if err := validateHeader(records[0]); err != nil {
		return inventory.DecodedCandidate{}, err
	}
	decoded, err := mapRecords(ctx, decoder.config, records[1:])
	if err != nil {
		return inventory.DecodedCandidate{}, err
	}
	if exceedsCoreLimits(decoded.Candidate) {
		return inventory.DecodedCandidate{}, decodeError(ErrorCSVLimitExceeded, 0, 0, "candidate")
	}
	digest := sha256.Sum256(raw)
	decoded.Candidate.Source.Digest = "sha256:" + hex.EncodeToString(digest[:])
	return decoded, nil
}

func readBounded(ctx context.Context, source io.Reader) ([]byte, error) {
	buffer := bytes.NewBuffer(make([]byte, 0, 32*1024))
	chunk := make([]byte, 32*1024)
	for {
		if ctx.Err() != nil {
			return nil, decodeError(ErrorInterrupted, 0, 0, "")
		}
		remaining := MaxInputBytes + 1 - buffer.Len()
		if remaining <= 0 {
			return nil, decodeError(ErrorCSVLimitExceeded, 0, 0, "")
		}
		window := chunk
		if remaining < len(window) {
			window = window[:remaining]
		}
		read, err := source.Read(window)
		if read > 0 {
			_, _ = buffer.Write(window[:read])
			if buffer.Len() > MaxInputBytes {
				return nil, decodeError(ErrorCSVLimitExceeded, 0, 0, "")
			}
		}
		if err == io.EOF {
			return buffer.Bytes(), nil
		}
		if err != nil {
			if ctx.Err() != nil {
				return nil, decodeError(ErrorInterrupted, 0, 0, "")
			}
			return nil, decodeError(ErrorCSVMalformed, 0, 0, "")
		}
		if read == 0 {
			return nil, decodeError(ErrorCSVMalformed, 0, 0, "")
		}
	}
}

func parseCSV(ctx context.Context, raw []byte) ([][]string, error) {
	reader := csv.NewReader(bytes.NewReader(raw))
	reader.FieldsPerRecord = -1
	reader.LazyQuotes = false
	reader.TrimLeadingSpace = false
	reader.ReuseRecord = false
	var records [][]string
	for {
		if ctx.Err() != nil {
			return nil, decodeError(ErrorInterrupted, 0, 0, "")
		}
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, decodeError(ErrorCSVMalformed, len(records)+1, 0, "")
		}
		records = append(records, record)
		if len(records) > MaxCSVRecords {
			return nil, decodeError(ErrorCSVLimitExceeded, len(records), 0, "")
		}
		if len(records) == 1 {
			reader.FieldsPerRecord = len(headerV1)
		}
	}
	if len(records) == 0 {
		return nil, decodeError(ErrorCSVEmpty, 0, 0, "")
	}
	return records, nil
}

func validateHeader(header []string) error {
	seen := make(map[string]bool, len(header))
	allowed := make(map[string]bool, len(headerV1))
	for _, field := range headerV1 {
		allowed[field] = true
	}
	for column, field := range header {
		if seen[field] {
			return decodeError(ErrorCSVHeaderDuplicate, 1, column+1, "header")
		}
		seen[field] = true
		if !allowed[field] {
			return decodeError(ErrorCSVHeaderUnknown, 1, column+1, "header")
		}
	}
	if len(header) != len(headerV1) {
		return decodeError(ErrorCSVHeaderMissing, 1, 0, "header")
	}
	for column, expected := range headerV1 {
		if header[column] != expected {
			return decodeError(ErrorCSVHeaderOrder, 1, column+1, "header")
		}
	}
	return nil
}

func fieldFor(column int) string {
	if column < 0 || column >= len(headerV1) {
		return ""
	}
	return headerV1[column]
}

func formulaProhibited(value string) bool {
	for _, r := range value {
		if unicode.IsSpace(r) {
			continue
		}
		return r == '=' || r == '+' || r == '-' || r == '@'
	}
	return false
}

func controlProhibited(value string) bool {
	for _, r := range value {
		if (r >= 0 && r < 0x20 && r != '\n' && r != '\r') || (r >= 0x7f && r <= 0x9f) || (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) || (r >= 0xfdd0 && r <= 0xfdef) || (r&0xffff == 0xfffe) || (r&0xffff == 0xffff) {
			return true
		}
	}
	return false
}

// Keep this fail-closed decoder check aligned with inventory/secrets.go. The
// core helper is deliberately unexported, so the profile cannot import an
// internal validation implementation or defer until after raw values escape.
var privatePrefixes = []string{"github_pat_", "ghp_", "gho_", "ghu_", "ghs_", "glpat-", "xoxb-", "xoxp-", "akia"}

func privateDataProhibited(value string) bool {
	lower := strings.ToLower(value)
	if strings.Contains(lower, "-----begin private key-----") || strings.Contains(lower, "-----begin rsa private key-----") || strings.Contains(lower, "-----begin openssh private key-----") {
		return true
	}
	trimmed := strings.TrimSpace(lower)
	for _, prefix := range privatePrefixes {
		if strings.HasPrefix(trimmed, prefix) {
			return true
		}
	}
	parsed, err := url.Parse(value)
	if err == nil && parsed.IsAbs() && parsed.User != nil {
		_, hasPassword := parsed.User.Password()
		return hasPassword
	}
	return false
}

func exceedsCoreLimits(candidate inventory.DraftCandidate) bool {
	primary := len(candidate.Assets) + len(candidate.Nodes) + len(candidate.Aliases) + len(candidate.Addresses) + len(candidate.Observations)
	if primary > inventory.MaxPrimaryRecords || len(candidate.Provenance) > inventory.MaxProvenance {
		return true
	}
	facts := 0
	for _, asset := range candidate.Assets {
		facts += len(asset.HardwareFacts)
		if len(asset.Identities) > inventory.MaxIdentities || len(asset.HardwareFacts) > inventory.MaxFactsPerAsset {
			return true
		}
	}
	return facts > inventory.MaxHardwareFacts
}

var _ inventory.CandidateDecoder = (*Decoder)(nil)
