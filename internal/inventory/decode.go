package inventory

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"time"
	"unicode/utf8"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/strictjson"
)

const (
	targetDraft       = "inventory-draft"
	targetDraftSchema = "inventory-draft-schema"
	targetContext     = "context"
)

type Error struct {
	Code   string
	Target string
}

func (err *Error) Error() string         { return fmt.Sprintf("%s: %s", err.Code, err.Target) }
func newError(code, target string) error { return &Error{Code: code, Target: target} }

type CandidateDecoder interface {
	Decode(context.Context, io.Reader) (DecodedCandidate, error)
}
type JSONDecoder struct{}

func (JSONDecoder) Decode(ctx context.Context, source io.Reader) (DecodedCandidate, error) {
	if source == nil {
		return DecodedCandidate{}, newError(generated.ErrorCodeInputInvalid, targetDraft)
	}
	raw, err := readBounded(ctx, source)
	if err != nil {
		return DecodedCandidate{}, err
	}
	if len(raw) == 0 || !utf8.Valid(raw) || bytes.HasPrefix(raw, []byte{0xef, 0xbb, 0xbf}) || bytes.IndexByte(raw, 0) >= 0 {
		return DecodedCandidate{}, newError(generated.ErrorCodeInputInvalid, targetDraft)
	}
	if err := strictjson.Scan(ctx, raw, strictjson.Limits{MaxDepth: MaxJSONDepth}); err != nil {
		if err == strictjson.ErrInterrupted {
			return DecodedCandidate{}, newError(generated.ErrorCodeInterrupted, targetContext)
		}
		return DecodedCandidate{}, newError(generated.ErrorCodeInputInvalid, targetDraft)
	}
	var envelope struct {
		Schema        string `json:"schema"`
		SchemaVersion string `json:"schemaVersion"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return DecodedCandidate{}, newError(generated.ErrorCodeInputInvalid, targetDraft)
	}
	if envelope.Schema != generated.SchemaIDInventoryDraftInput || envelope.SchemaVersion != "1.0.0" {
		return DecodedCandidate{}, newError(generated.ErrorCodeSchemaUnsupported, targetDraftSchema)
	}
	var input generated.InventoryDraftInput
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		return DecodedCandidate{}, newError(generated.ErrorCodeInputInvalid, targetDraft)
	}
	candidate, err := mapGeneratedInput(input)
	if err != nil {
		return DecodedCandidate{}, err
	}
	digest := sha256.Sum256(raw)
	candidate.Source.Digest = "sha256:" + hex.EncodeToString(digest[:])
	return DecodedCandidate{Candidate: candidate}, nil
}

func readBounded(ctx context.Context, source io.Reader) ([]byte, error) {
	buffer := bytes.NewBuffer(make([]byte, 0, 32*1024))
	chunk := make([]byte, 32*1024)
	for {
		if ctx.Err() != nil {
			return nil, newError(generated.ErrorCodeInterrupted, targetContext)
		}
		read, err := source.Read(chunk)
		if read > 0 {
			if buffer.Len()+read > MaxInputBytes {
				return nil, newError(generated.ErrorCodeInputInvalid, targetDraft)
			}
			_, _ = buffer.Write(chunk[:read])
		}
		if err == io.EOF {
			return buffer.Bytes(), nil
		}
		if err != nil {
			if ctx.Err() != nil {
				return nil, newError(generated.ErrorCodeInterrupted, targetContext)
			}
			return nil, newError(generated.ErrorCodeInputInvalid, targetDraft)
		}
		if read == 0 {
			return nil, newError(generated.ErrorCodeInputInvalid, targetDraft)
		}
	}
}

func mapGeneratedInput(input generated.InventoryDraftInput) (DraftCandidate, error) {
	capturedAt, err := parseTimestamp(input.Source.CapturedAt)
	if err != nil {
		return DraftCandidate{}, newError(generated.ErrorCodeInputInvalid, targetDraft)
	}
	candidate := DraftCandidate{Source: SourceDescriptor{Kind: input.Source.Kind, AdapterKind: input.Source.AdapterKind, AdapterVersion: input.Source.AdapterVersion, SourceRevision: input.Source.SourceRevision, CapturedAt: capturedAt}}
	for _, value := range input.Assets {
		asset := DraftAsset{ID: LocalID(value.ID), Kind: AssetKind(value.Kind), Lifecycle: AssetLifecycle(value.Lifecycle)}
		for _, identity := range value.Identities {
			asset.Identities = append(asset.Identities, DraftIdentity{Kind: identity.Kind, Value: identity.Value, Quarantined: identity.Quarantined})
		}
		for _, fact := range value.HardwareFacts {
			asset.HardwareFacts = append(asset.HardwareFacts, DraftHardwareFact{ID: LocalID(fact.ID), Kind: fact.Kind, IntegerValue: fact.IntegerValue, TextValue: fact.TextValue, Unit: fact.Unit})
		}
		candidate.Assets = append(candidate.Assets, asset)
	}
	for _, value := range input.Nodes {
		candidate.Nodes = append(candidate.Nodes, DraftNode{ID: LocalID(value.ID), AssetID: LocalID(value.AssetID), ParentID: LocalID(value.ParentID)})
	}
	for _, value := range input.Aliases {
		candidate.Aliases = append(candidate.Aliases, DraftAlias{ID: LocalID(value.ID), TargetID: LocalID(value.TargetID), Value: value.Value})
	}
	for _, value := range input.Addresses {
		candidate.Addresses = append(candidate.Addresses, DraftAddress{ID: LocalID(value.ID), NodeID: LocalID(value.NodeID), Value: value.Value})
	}
	for _, value := range input.Observations {
		observedAt, parseErr := parseTimestamp(value.ObservedAt)
		if parseErr != nil {
			return DraftCandidate{}, newError(generated.ErrorCodeInputInvalid, targetDraft)
		}
		candidate.Observations = append(candidate.Observations, DraftObservation{ID: LocalID(value.ID), SubjectID: LocalID(value.SubjectID), Kind: value.Kind, Value: value.Value, ObservedAt: observedAt})
	}
	for _, value := range input.Provenance {
		capturedAt, parseErr := parseTimestamp(value.CapturedAt)
		if parseErr != nil {
			return DraftCandidate{}, newError(generated.ErrorCodeInputInvalid, targetDraft)
		}
		candidate.Provenance = append(candidate.Provenance, FieldProvenance{RecordKind: value.RecordKind, RecordID: LocalID(value.RecordID), FieldPath: value.FieldPath, Locator: value.Locator, CapturedAt: capturedAt, AdapterVersion: value.AdapterVersion, ValueStatus: value.ValueStatus})
	}
	return candidate, nil
}

func parseTimestamp(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, err
	}
	return parsed.UTC(), nil
}
