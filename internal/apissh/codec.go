// Package apissh encodes and validates the bounded framing used by the
// constrained SSH transport. It does not authenticate SSH identities,
// authorize operations, compare recovery epochs, or dispatch requests.
package apissh

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

const (
	Protocol = "vegastack-labs.api-ssh"
	Version  = "1.0.0"

	maxHeaderBytes          = 16 << 10
	maxRequestPayloadBytes  = 8 << 20
	maxResponsePayloadBytes = 24 << 20
)

var operationPathPattern = regexp.MustCompile(`^/api/v1/[A-Za-z0-9._:-]+(?:/[A-Za-z0-9._:-]+)*$`)

type Error struct {
	Code   string
	Target string
	cause  error
}

func (err *Error) Error() string { return err.Code + ": " + err.Target }
func (err *Error) Unwrap() error { return err.cause }

func ErrorCode(err error) string {
	var frameError *Error
	if errors.As(err, &frameError) {
		return frameError.Code
	}
	return ""
}

type Request struct {
	Header             generated.ApiSshRequestFrameHeader
	Method             string
	Path               string
	Payload            []byte
	ActualPayloadBytes int64
}

type Response struct {
	Header             generated.ApiSshResponseFrameHeader
	Envelope           generated.RunResult
	RawEnvelope        []byte
	ActualPayloadBytes int64
}

func NewRequestHeader(requestID, sshPrincipalID, deviceID, operation string, arguments []string, recoveryEpoch int64, payload []byte) (generated.ApiSshRequestFrameHeader, error) {
	header := generated.ApiSshRequestFrameHeader{
		Protocol:             Protocol,
		Version:              Version,
		RequestID:            requestID,
		SSHPrincipalID:       sshPrincipalID,
		DeviceID:             deviceID,
		Operation:            operation,
		Arguments:            append([]string{}, arguments...),
		PayloadDigest:        payloadDigest(payload),
		DeclaredPayloadBytes: int64(len(payload)),
		ActualPayloadBytes:   int64(len(payload)),
		RecoveryEpoch:        recoveryEpoch,
	}
	if _, _, err := validateRequestHeader(header); err != nil {
		return generated.ApiSshRequestFrameHeader{}, err
	}
	return header, nil
}

func WriteRequest(output io.Writer, header generated.ApiSshRequestFrameHeader, payload []byte) error {
	if output == nil {
		return frameError(generated.ErrorCodeInputInvalid, "api-ssh-request-frame", nil)
	}
	if _, _, err := validateRequestHeader(header); err != nil {
		return err
	}
	if err := validatePayload(payload, header.DeclaredPayloadBytes, header.ActualPayloadBytes, maxRequestPayloadBytes, header.PayloadDigest); err != nil {
		return err
	}
	return writeFrame(output, header, payload, "api-ssh-request-frame")
}

func ReadRequest(input io.Reader) (Request, error) {
	var zero Request
	reader, rawHeader, err := readFrameHeader(input, "api-ssh-request-frame")
	if err != nil {
		return zero, err
	}
	var header generated.ApiSshRequestFrameHeader
	if err := decodeHeader(rawHeader, generated.SchemaIDApiSshRequestFrameHeader, &header, "api-ssh-request-frame"); err != nil {
		return zero, err
	}
	method, path, err := validateRequestHeader(header)
	if err != nil {
		return zero, err
	}
	payload, actual, err := readRequestPayload(reader, header)
	if err != nil {
		return zero, err
	}
	return Request{Header: header, Method: method, Path: path, Payload: payload, ActualPayloadBytes: actual}, nil
}

func WriteResponse(output io.Writer, requestID string, envelope generated.RunResult) error {
	if output == nil {
		return frameError(generated.ErrorCodeInputInvalid, "api-ssh-response-frame", nil)
	}
	if requestID == "" || envelope.RequestID != requestID {
		return frameError(generated.ErrorCodeStateConflict, "api-ssh-response-frame", nil)
	}
	payload, err := canonicalEnvelope(envelope)
	if err != nil {
		return err
	}
	header := generated.ApiSshResponseFrameHeader{
		Protocol: Protocol, Version: Version, RequestID: requestID,
		DeclaredPayloadBytes: int64(len(payload)), ActualPayloadBytes: int64(len(payload)),
	}
	return writeFrame(output, header, payload, "api-ssh-response-frame")
}

func ReadResponse(input io.Reader, expectedRequestID string) (Response, error) {
	var zero Response
	reader, rawHeader, err := readFrameHeader(input, "api-ssh-response-frame")
	if err != nil {
		return zero, err
	}
	var header generated.ApiSshResponseFrameHeader
	if err := decodeHeader(rawHeader, generated.SchemaIDApiSshResponseFrameHeader, &header, "api-ssh-response-frame"); err != nil {
		return zero, err
	}
	if expectedRequestID == "" || header.RequestID != expectedRequestID {
		return zero, frameError(generated.ErrorCodeStateConflict, "api-ssh-response-frame", nil)
	}
	payload, actual, err := readPayload(reader, header.DeclaredPayloadBytes, maxResponsePayloadBytes, "api-ssh-response-frame")
	if err != nil {
		return zero, err
	}
	if header.ActualPayloadBytes != actual || header.DeclaredPayloadBytes != actual {
		return zero, frameError(generated.ErrorCodeInputInvalid, "api-ssh-response-frame", nil)
	}
	envelope, err := decodeEnvelope(payload)
	if err != nil {
		return zero, err
	}
	if envelope.RequestID != header.RequestID {
		return zero, frameError(generated.ErrorCodeStateConflict, "api-ssh-response-frame", nil)
	}
	return Response{Header: header, Envelope: envelope, RawEnvelope: append([]byte(nil), payload...), ActualPayloadBytes: actual}, nil
}

func ParseOperation(operation string) (method, path string, err error) {
	if operation == "sqlite-query" {
		return "", "", frameError(generated.ErrorCodeAuthorizationDenied, "api-ssh-request-operation", nil)
	}
	if len(operation) == 0 || len(operation) > 512 || !utf8.ValidString(operation) {
		return "", "", frameError(generated.ErrorCodeInputInvalid, "api-ssh-request-operation", nil)
	}
	parts := strings.Split(operation, " ")
	if len(parts) != 2 || (parts[0] != "GET" && parts[0] != "POST") || !operationPathPattern.MatchString(parts[1]) {
		return "", "", frameError(generated.ErrorCodeInputInvalid, "api-ssh-request-operation", nil)
	}
	return parts[0], parts[1], nil
}

func validateRequestHeader(header generated.ApiSshRequestFrameHeader) (string, string, error) {
	if header.Protocol != Protocol || header.Version != Version {
		return "", "", frameError(generated.ErrorCodeSchemaUnsupported, "api-ssh-request-frame", nil)
	}
	raw, err := json.Marshal(header)
	if err != nil || generated.ValidateContractJSON(generated.SchemaIDApiSshRequestFrameHeader, raw, generated.ContractExact) != nil {
		return "", "", frameError(generated.ErrorCodeInputInvalid, "api-ssh-request-frame", err)
	}
	method, path, err := ParseOperation(header.Operation)
	if err != nil {
		return "", "", err
	}
	for _, argument := range header.Arguments {
		if !validArgument(argument) {
			return "", "", frameError(generated.ErrorCodeInputInvalid, "api-ssh-request-arguments", nil)
		}
	}
	return method, path, nil
}

func validArgument(argument string) bool {
	if len(argument) == 0 || len(argument) > 512 || !utf8.ValidString(argument) {
		return false
	}
	for _, character := range argument {
		if character <= 0x20 || character == 0x7f || strings.ContainsRune("/\\;&|`$><(){}[]*?!~\"'", character) {
			return false
		}
	}
	return true
}

func decodeHeader(raw []byte, schemaID string, destination any, target string) error {
	if err := json.Unmarshal(raw, destination); err != nil {
		return frameError(generated.ErrorCodeInputInvalid, target, err)
	}
	// Protocol and version are decoded once before the strict generated schema
	// check so incompatible peers receive the stable compatibility category.
	var identity struct {
		Protocol string `json:"protocol"`
		Version  string `json:"version"`
	}
	if err := json.Unmarshal(raw, &identity); err != nil {
		return frameError(generated.ErrorCodeInputInvalid, target, err)
	}
	if identity.Protocol != Protocol || identity.Version != Version {
		return frameError(generated.ErrorCodeSchemaUnsupported, target, nil)
	}
	if err := generated.ValidateContractJSON(schemaID, raw, generated.ContractExact); err != nil {
		return frameError(generated.ErrorCodeInputInvalid, target, err)
	}
	return nil
}

func readFrameHeader(input io.Reader, target string) (*bufio.Reader, []byte, error) {
	if input == nil {
		return nil, nil, frameError(generated.ErrorCodeInputInvalid, target, nil)
	}
	reader := bufio.NewReaderSize(input, maxHeaderBytes+1)
	raw, err := reader.ReadSlice('\n')
	if err != nil || len(raw) < 3 || len(raw) > maxHeaderBytes+1 {
		return nil, nil, frameError(generated.ErrorCodeInputInvalid, target, err)
	}
	return reader, append([]byte(nil), raw[:len(raw)-1]...), nil
}

func readPayload(reader io.Reader, declared, maximum int64, target string) ([]byte, int64, error) {
	if declared < 0 || declared > maximum {
		return nil, 0, frameError(generated.ErrorCodeInputInvalid, target, nil)
	}
	payload, err := io.ReadAll(io.LimitReader(reader, declared+1))
	if err != nil || int64(len(payload)) != declared {
		return nil, int64(len(payload)), frameError(generated.ErrorCodeInputInvalid, target, err)
	}
	return payload, int64(len(payload)), nil
}

func readRequestPayload(reader io.Reader, header generated.ApiSshRequestFrameHeader) ([]byte, int64, error) {
	if header.DeclaredPayloadBytes < 0 || header.DeclaredPayloadBytes > maxRequestPayloadBytes {
		return nil, 0, frameError(generated.ErrorCodeInputInvalid, "api-ssh-request-frame", nil)
	}
	hasher := sha256.New()
	payload, err := io.ReadAll(io.TeeReader(io.LimitReader(reader, header.DeclaredPayloadBytes+1), hasher))
	actual := int64(len(payload))
	if err != nil || actual != header.DeclaredPayloadBytes || actual != header.ActualPayloadBytes {
		return nil, actual, frameError(generated.ErrorCodeInputInvalid, "api-ssh-request-frame", err)
	}
	actualDigest := "sha256:" + hex.EncodeToString(hasher.Sum(nil))
	if actualDigest != header.PayloadDigest {
		return nil, actual, frameError(generated.ErrorCodeIntegrityFailure, "api-ssh-request-payload", nil)
	}
	return payload, actual, nil
}

func validatePayload(payload []byte, declared, claimedActual, maximum int64, expectedDigest string) error {
	actual := int64(len(payload))
	if actual > maximum || declared != actual || claimedActual != actual {
		return frameError(generated.ErrorCodeInputInvalid, "api-ssh-request-frame", nil)
	}
	if payloadDigest(payload) != expectedDigest {
		return frameError(generated.ErrorCodeIntegrityFailure, "api-ssh-request-payload", nil)
	}
	return nil
}

func writeFrame(output io.Writer, header any, payload []byte, target string) error {
	raw, err := json.Marshal(header)
	if err != nil {
		return frameError(generated.ErrorCodeInputInvalid, target, err)
	}
	raw = append(raw, '\n')
	if _, err := output.Write(raw); err != nil {
		return frameError(generated.ErrorCodeDependencyUnavailable, target, err)
	}
	if _, err := output.Write(payload); err != nil {
		return frameError(generated.ErrorCodeDependencyUnavailable, target, err)
	}
	return nil
}

func canonicalEnvelope(envelope generated.RunResult) ([]byte, error) {
	raw, err := json.Marshal(envelope)
	if err != nil || generated.ValidateContractJSON(generated.SchemaIDRunResult, raw, generated.ContractExact) != nil {
		return nil, frameError(generated.ErrorCodeInputInvalid, "api-ssh-response-envelope", err)
	}
	if len(raw)+1 > maxResponsePayloadBytes {
		return nil, frameError(generated.ErrorCodeInputInvalid, "api-ssh-response-envelope", nil)
	}
	return append(raw, '\n'), nil
}

func decodeEnvelope(raw []byte) (generated.RunResult, error) {
	var envelope generated.RunResult
	if len(raw) < 2 || raw[len(raw)-1] != '\n' || json.Unmarshal(raw, &envelope) != nil {
		return envelope, frameError(generated.ErrorCodeInputInvalid, "api-ssh-response-envelope", nil)
	}
	canonical, err := canonicalEnvelope(envelope)
	if err != nil || !bytes.Equal(raw, canonical) {
		return generated.RunResult{}, frameError(generated.ErrorCodeInputInvalid, "api-ssh-response-envelope", err)
	}
	return envelope, nil
}

func payloadDigest(payload []byte) string {
	digest := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func frameError(code, target string, cause error) error {
	return &Error{Code: code, Target: target, cause: cause}
}
