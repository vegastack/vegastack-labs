package contractgen

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/vegastack/vegastack-labs/internal/metadata"
)

const browserClientPath = "web/generated/read-api.ts"

func browserReadEndpoints(registry metadata.Registry) ([]metadata.EndpointDefinition, error) {
	endpoints := make([]metadata.EndpointDefinition, 0, len(registry.Endpoints))
	for _, endpoint := range registry.Endpoints {
		browser := false
		for _, audience := range endpoint.Audiences {
			browser = browser || audience == metadata.AudienceBrowser
		}
		contractedPhase4 := endpoint.OwnerPhase == "4" && endpoint.Availability == metadata.AvailabilityPlanned
		availableRead := endpoint.Availability == metadata.AvailabilityAvailable && endpoint.Method == "GET"
		if !browser || (!contractedPhase4 && !availableRead) {
			continue
		}
		if !strings.HasPrefix(endpoint.Path, "/api/v1/") || strings.Contains(endpoint.Path, "://") || (endpoint.Method != "GET" && endpoint.Method != "POST") {
			return nil, artifactError("GENERATED_BROWSER_ENDPOINT_UNSAFE", browserClientPath)
		}
		endpoints = append(endpoints, endpoint)
	}
	sort.Slice(endpoints, func(left, right int) bool { return endpoints[left].ID < endpoints[right].ID })
	return endpoints, nil
}

func browserSchemaGraph(registry metadata.Registry, endpoints []metadata.EndpointDefinition) ([]metadata.SchemaDefinition, error) {
	definitions := make(map[string]metadata.SchemaDefinition, len(registry.Schemas))
	for _, definition := range registry.Schemas {
		definition.Fields = append([]metadata.FieldDefinition(nil), definition.Fields...)
		if definition.ID == "vegastack-labs.dev/result-error" {
			codes := make([]string, 0, len(registry.Errors))
			for _, failure := range registry.Errors {
				codes = append(codes, failure.Code)
			}
			for index := range definition.Fields {
				if definition.Fields[index].JSONName == "code" {
					definition.Fields[index].Enum = codes
				}
			}
		}
		definitions[definition.ID] = definition
	}
	wanted := map[string]bool{runResultSchemaID: true}
	for _, identifier := range []string{
		"vegastack-labs.dev/declaration-revision",
		"vegastack-labs.dev/plan",
		"vegastack-labs.dev/authorization-decision",
		"vegastack-labs.dev/acknowledgement",
		"vegastack-labs.dev/run",
		"vegastack-labs.dev/executor-lease",
		"vegastack-labs.dev/execution-receipt",
	} {
		wanted[identifier] = true
	}
	for _, endpoint := range endpoints {
		wanted[endpoint.DataSchema] = true
		if endpoint.QuerySchema != "" {
			wanted[endpoint.QuerySchema] = true
		}
		if endpoint.RequestSchema != "" {
			wanted[endpoint.RequestSchema] = true
		}
	}
	var visit func(string) error
	visit = func(identifier string) error {
		definition, ok := definitions[identifier]
		if !ok {
			return artifactError("GENERATED_SCHEMA_MISSING", browserClientPath)
		}
		for _, field := range definition.Fields {
			if browserSecretField(field.JSONName) || (field.AdditionalProperties && !browserEnvelopeDataField(definition.ID, field.JSONName)) {
				return artifactError("GENERATED_BROWSER_SCHEMA_UNSAFE", browserClientPath)
			}
			for _, reference := range []string{field.Ref, field.ItemRef} {
				if reference == "" || wanted[reference] {
					continue
				}
				wanted[reference] = true
				if err := visit(reference); err != nil {
					return err
				}
			}
		}
		return nil
	}
	for identifier := range wanted {
		if err := visit(identifier); err != nil {
			return nil, err
		}
	}
	graph := make([]metadata.SchemaDefinition, 0, len(wanted))
	for identifier := range wanted {
		graph = append(graph, definitions[identifier])
	}
	sort.Slice(graph, func(left, right int) bool { return graph[left].ID < graph[right].ID })
	return graph, nil
}

func browserSecretField(name string) bool {
	var compact strings.Builder
	for _, character := range strings.ToLower(name) {
		if unicode.IsLetter(character) || unicode.IsDigit(character) {
			compact.WriteRune(character)
		}
	}
	normalized := compact.String()
	for _, safe := range []string{"authorizationbranch", "authorizationdecisionid", "idempotencykey", "keyfingerprint", "keyid", "publickeyid"} {
		if normalized == safe {
			return false
		}
	}
	for _, sensitive := range []string{
		"password", "passwd", "passphrase", "plaintext", "privatekey", "secret", "credential", "token",
		"apikey", "accesskey", "signingkey", "encryptionkey", "decryptionkey", "keymaterial",
		"bearer", "authorization", "authheader", "cookie", "jwt", "samlassertion", "clientassertion",
	} {
		if strings.Contains(normalized, sensitive) {
			return true
		}
	}
	return false
}

func browserEnvelopeDataField(schemaID, fieldName string) bool {
	// RunResult.data is decoded immediately against the endpoint's closed data
	// schema. It is the sole open carrier allowed into the generated graph.
	return schemaID == runResultSchemaID && fieldName == "data"
}

type browserSchemaRule struct {
	ID     string             `json:"id"`
	Fields []browserFieldRule `json:"fields"`
}

type browserFieldRule struct {
	Name                 string             `json:"name"`
	Kind                 metadata.ValueKind `json:"kind"`
	Required             bool               `json:"required"`
	Nullable             bool               `json:"nullable"`
	Ref                  string             `json:"ref,omitempty"`
	ItemRef              string             `json:"itemRef,omitempty"`
	ItemKind             metadata.ValueKind `json:"itemKind,omitempty"`
	Enum                 []string           `json:"enum,omitempty"`
	AdditionalProperties bool               `json:"additionalProperties,omitempty"`
	Pattern              string             `json:"pattern,omitempty"`
	MinLength            *int               `json:"minLength,omitempty"`
	MaxLength            *int               `json:"maxLength,omitempty"`
	Minimum              *int64             `json:"minimum,omitempty"`
	Maximum              *int64             `json:"maximum,omitempty"`
	MinItems             *int               `json:"minItems,omitempty"`
	MaxItems             *int               `json:"maxItems,omitempty"`
	UniqueItems          bool               `json:"uniqueItems,omitempty"`
}

func renderBrowserContractGraph(endpoints []metadata.EndpointDefinition, schemas []metadata.SchemaDefinition, errors []metadata.ErrorDefinition, lifecycle metadata.LifecycleDefinition) []byte {
	var output bytes.Buffer
	output.WriteString("// Code generated by go run ./tooling/generate-contracts --write; DO NOT EDIT.\n")
	output.WriteString("// Browser-safe available reads and planned Phase 4 contracts:\n")
	for _, endpoint := range endpoints {
		output.WriteString("// " + endpoint.ID + "\n")
	}
	output.WriteString("\n")
	fmt.Fprintf(&output, "export const PLAN_VALIDITY_SECONDS = %d;\n", lifecycle.PlanValiditySeconds)
	fmt.Fprintf(&output, "export const EXECUTOR_LEASE_SECONDS = %d;\n", lifecycle.LeaseDurationSeconds)
	fmt.Fprintf(&output, "export const EXECUTOR_CHECK_IN_SECONDS = %d;\n", lifecycle.ExecutorCheckInSeconds)
	transitions, _ := json.Marshal(lifecycle.RunTransitions)
	output.WriteString("export const RUN_TRANSITIONS = ")
	output.Write(transitions)
	output.WriteString(" as const;\n\n")
	for _, schema := range schemas {
		renderBrowserType(&output, schema)
	}
	stableCodes := make([]string, 0, len(errors))
	for _, definition := range errors {
		stableCodes = append(stableCodes, definition.Code)
	}
	sort.Strings(stableCodes)
	encodedCodes, _ := json.Marshal(stableCodes)
	output.WriteString("export const STABLE_ERROR_CODES = ")
	output.Write(encodedCodes)
	output.WriteString(" as const;\n")
	output.WriteString(`export type StableErrorCode = (typeof STABLE_ERROR_CODES)[number];
export type ApiFailureKind = "api" | "network" | "malformed-json" | "schema-mismatch" | "unsupported-version" | "cancelled";

export class ReadClientError extends Error {
  readonly kind: ApiFailureKind;
  readonly code: StableErrorCode;
  readonly target: string;
  readonly retryable: boolean;
  readonly correlationId: string | null;

  constructor(kind: ApiFailureKind, code: StableErrorCode, target: string, retryable = false, correlationId: string | null = null) {
    super(code);
    this.name = "ReadClientError";
    this.kind = kind;
    this.code = code;
    this.target = target;
    this.retryable = retryable;
    this.correlationId = correlationId;
  }
}

type SchemaRule = { readonly id: string; readonly fields: ReadonlyArray<FieldRule> };
type FieldRule = {
  readonly name: string;
  readonly kind: "string" | "boolean" | "integer" | "object" | "array";
  readonly required: boolean;
  readonly nullable: boolean;
  readonly ref?: string;
  readonly itemRef?: string;
  readonly itemKind?: "string" | "boolean" | "integer" | "object" | "array";
  readonly enum?: ReadonlyArray<string>;
  readonly additionalProperties?: boolean;
  readonly pattern?: string;
  readonly minLength?: number;
  readonly maxLength?: number;
  readonly minimum?: number;
  readonly maximum?: number;
  readonly minItems?: number;
  readonly maxItems?: number;
  readonly uniqueItems?: boolean;
};

const SCHEMAS: ReadonlyArray<SchemaRule> = `)
	rules := make([]browserSchemaRule, 0, len(schemas))
	for _, schema := range schemas {
		rule := browserSchemaRule{ID: schema.ID, Fields: make([]browserFieldRule, 0, len(schema.Fields))}
		for _, field := range schema.Fields {
			rule.Fields = append(rule.Fields, browserFieldRule{
				Name: field.JSONName, Kind: field.Kind, Required: field.Required, Nullable: field.Nullable,
				Ref: field.Ref, ItemRef: field.ItemRef, ItemKind: field.ItemKind, Enum: field.Enum,
				AdditionalProperties: field.AdditionalProperties, Pattern: field.Pattern,
				MinLength: field.MinLength, MaxLength: field.MaxLength, Minimum: field.Minimum, Maximum: field.Maximum,
				MinItems: field.MinItems, MaxItems: field.MaxItems, UniqueItems: field.UniqueItems,
			})
		}
		rules = append(rules, rule)
	}
	encoded, _ := json.MarshalIndent(rules, "", "  ")
	output.Write(encoded)
	output.WriteString(`;

function mismatch(path: string, reason: string): never {
  throw new ReadClientError("schema-mismatch", "INTEGRITY_FAILURE", path + ": " + reason);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function stringLength(value: string): number {
  return Array.from(value).length;
}

function decodePrimitive(kind: FieldRule["kind"], value: unknown, path: string): unknown {
  if (kind === "string" && typeof value === "string") return value;
  if (kind === "boolean" && typeof value === "boolean") return value;
  if (kind === "integer" && typeof value === "number" && Number.isSafeInteger(value)) return value;
  if (kind === "object" && isRecord(value)) return value;
  if (kind === "array" && Array.isArray(value)) return value;
  return mismatch(path, "wrong value kind");
}

function decodeField(rule: FieldRule, value: unknown, path: string): unknown {
  if (value === null) {
    if (rule.nullable) return null;
    return mismatch(path, "null is not allowed");
  }
  let decoded: unknown;
  if (rule.ref) {
    decoded = decodeSchema(rule.ref, value, path);
  } else if (rule.kind === "array") {
    if (!Array.isArray(value)) return mismatch(path, "wrong value kind");
    decoded = value.map((item, index) => rule.itemRef
      ? decodeSchema(rule.itemRef, item, path + "[" + index + "]")
      : decodePrimitive(rule.itemKind ?? "object", item, path + "[" + index + "]"));
  } else {
    decoded = decodePrimitive(rule.kind, value, path);
    if (rule.kind === "object" && !rule.additionalProperties && Object.keys(decoded as object).length !== 0) {
      return mismatch(path, "additional property is not allowed");
    }
  }
  if (typeof decoded === "string") {
    const length = stringLength(decoded);
    if (rule.enum && !rule.enum.includes(decoded)) return mismatch(path, "value is not in enum");
    if (rule.pattern && !(new RegExp(rule.pattern, "u")).test(decoded)) return mismatch(path, "pattern mismatch");
    if (rule.minLength !== undefined && length < rule.minLength) return mismatch(path, "string is too short");
    if (rule.maxLength !== undefined && length > rule.maxLength) return mismatch(path, "string is too long");
  }
  if (typeof decoded === "number") {
    if (rule.minimum !== undefined && decoded < rule.minimum) return mismatch(path, "number is below minimum");
    if (rule.maximum !== undefined && decoded > rule.maximum) return mismatch(path, "number is above maximum");
  }
  if (Array.isArray(decoded)) {
    if (rule.minItems !== undefined && decoded.length < rule.minItems) return mismatch(path, "array is too short");
    if (rule.maxItems !== undefined && decoded.length > rule.maxItems) return mismatch(path, "array is too long");
    if (rule.uniqueItems) {
      const fingerprints = decoded.map((item) => JSON.stringify(item));
      if (new Set(fingerprints).size !== fingerprints.length) return mismatch(path, "array items are not unique");
    }
  }
  return decoded;
}

function decodeSchema(identifier: string, value: unknown, path = identifier): Record<string, unknown> {
  const rule = SCHEMAS.find((candidate) => candidate.id === identifier);
  if (!rule) return mismatch(path, "schema is unavailable");
  if (!isRecord(value)) return mismatch(path, "expected object");
  const fieldNames = new Set(rule.fields.map((field) => field.name));
  for (const name of Object.keys(value)) {
    if (!fieldNames.has(name)) return mismatch(path + "." + name, "additional property is not allowed");
  }
  const result: Record<string, unknown> = {};
  for (const field of rule.fields) {
    if (!Object.hasOwn(value, field.name)) {
      if (field.required) return mismatch(path + "." + field.name, "required property is missing");
      continue;
    }
    result[field.name] = decodeField(field, value[field.name], path + "." + field.name);
  }
  return result;
}

function unsafeCompatibleField(name: string): boolean {
  const normalized = name.toLowerCase().replace(/[^a-z0-9]/g, "");
  return ["password", "passwd", "passphrase", "plaintext", "privatekey", "secret", "credential", "token", "apikey", "accesskey", "bearer", "authorization", "cookie", "jwt"].some((part) => normalized.includes(part));
}

export function decodePhase4Contract(identifier: string, value: unknown, compatibleRead = false): Record<string, unknown> {
  if (!compatibleRead) return decodeSchema(identifier, value);
  if (!isRecord(value)) return mismatch(identifier, "expected object");
  const version = value.schemaVersion;
  if (typeof version !== "string" || !/^1\.\d+\.\d+$/.test(version)) {
    throw new ReadClientError("unsupported-version", "SCHEMA_UNSUPPORTED", identifier);
  }
  const rule = SCHEMAS.find((candidate) => candidate.id === identifier);
  if (!rule) return mismatch(identifier, "schema is unavailable");
  const fieldNames = new Set(rule.fields.map((field) => field.name));
  const known: Record<string, unknown> = {};
  for (const [name, fieldValue] of Object.entries(value)) {
    if (fieldNames.has(name)) known[name] = fieldValue;
    else if (unsafeCompatibleField(name)) return mismatch(identifier + "." + name, "unsafe additive field");
  }
  return decodeSchema(identifier, known);
}

export function validateRunTransition(from: string, to: string): void {
  if (!RUN_TRANSITIONS.some((transition) => transition.from === from && transition.to === to)) {
    return mismatch("run.status", "invalid run transition");
  }
}

export function validateExecutionReceiptBinding(leaseValue: unknown, receiptValue: unknown): void {
  const lease = decodeSchema("vegastack-labs.dev/executor-lease", leaseValue);
  const receipt = decodeSchema("vegastack-labs.dev/execution-receipt", receiptValue);
  for (const name of ["leaseId", "planId", "planDigest", "runId", "stepId", "operationId", "executorId", "adapterId", "targetId", "artifactDigest", "bindingDigest", "nonceDigest", "recoveryEpoch"]) {
    if (lease[name] !== receipt[name]) return mismatch("execution-receipt." + name, "binding widened or changed");
  }
}

export function validatePlanTiming(value: unknown): void {
  const plan = decodeSchema("vegastack-labs.dev/plan", value);
  const created = Date.parse(plan.createdAt as string);
  const expires = Date.parse(plan.expiresAt as string);
  if (!Number.isFinite(created) || expires - created !== PLAN_VALIDITY_SECONDS * 1000) return mismatch("plan.expiresAt", "plan expiry must be exactly 30 minutes");
}

export function validateLeaseTiming(value: unknown): void {
  const lease = decodeSchema("vegastack-labs.dev/executor-lease", value);
  const claimed = Date.parse(lease.claimedAt as string);
  const renew = Date.parse(lease.renewAfter as string);
  const expires = Date.parse(lease.leaseExpiresAt as string);
  const maximum = Date.parse(lease.maximumExpiresAt as string);
  if (!Number.isFinite(claimed) || renew - claimed !== EXECUTOR_CHECK_IN_SECONDS * 1000 || expires - claimed !== EXECUTOR_LEASE_SECONDS * 1000 || maximum !== expires) return mismatch("executor-lease", "invalid lease timing or maximum expiry");
}

`)
	for _, schema := range schemas {
		name := schemaGoName(schema.ID)
		fmt.Fprintf(&output, "function decode%s(value: unknown): %s {\n  return decodeSchema(%s, value) as unknown as %s;\n}\n\n", name, name, strconv.Quote(schema.ID), name)
	}
	output.WriteString(`export type FetchTransport = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;
export type RequestOptions = { readonly signal?: AbortSignal };
export type StreamOptions = RequestOptions & { readonly lastEventId?: string };
export type ReadEnvelope = Omit<RunResult, "schemaVersion"> & { readonly schemaVersion: string };
export type ReadResult<T> = Omit<ReadEnvelope, "data"> & { readonly data: T };

function decodeReadEnvelope(value: unknown, operation: string): ReadEnvelope {
  if (!isRecord(value)) return mismatch(operation, "expected result object");
  const version = value.schemaVersion;
  if (typeof version !== "string" || !/^\d+\.\d+\.\d+$/.test(version)) return mismatch(operation + ".schemaVersion", "invalid version");
  if (Number.parseInt(version.split(".")[0] ?? "", 10) !== 1) {
    throw new ReadClientError("unsupported-version", "SCHEMA_UNSUPPORTED", operation);
  }
  const runResultRule = SCHEMAS.find((candidate) => candidate.id === "vegastack-labs.dev/run-result");
  const canonicalVersion = runResultRule?.fields.find((field) => field.name === "schemaVersion")?.enum?.[0];
  if (!canonicalVersion) return mismatch(operation + ".schemaVersion", "version rule is unavailable");
  const envelope = decodeRunResult({ ...value, schemaVersion: canonicalVersion });
  return { ...envelope, schemaVersion: version };
}

async function readJSON(response: Response, operation: string, signal?: AbortSignal): Promise<unknown> {
  const contentLength = Number(response.headers.get("content-length") ?? "0");
  if (Number.isFinite(contentLength) && contentLength > 4_194_304) return mismatch(operation, "response is too large");
  let body: Uint8Array;
  try {
    if (!response.body) throw new SyntaxError("empty response");
    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let size = 0;
    for (;;) {
      const next = await reader.read();
      if (next.done) break;
      size += next.value.byteLength;
      if (size > 4_194_304) {
        await reader.cancel();
        return mismatch(operation, "response is too large");
      }
      chunks.push(next.value);
    }
    body = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) {
      body.set(chunk, offset);
      offset += chunk.byteLength;
    }
  } catch (error) {
    if (error instanceof ReadClientError) throw error;
    if (cancelled(signal, error)) throw new ReadClientError("cancelled", "INTERRUPTED", operation);
    if (!(error instanceof SyntaxError)) throw new ReadClientError("network", "DEPENDENCY_UNAVAILABLE", operation, true);
    throw new ReadClientError("malformed-json", "INTEGRITY_FAILURE", operation);
  }
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(body));
  } catch {
    throw new ReadClientError("malformed-json", "INTEGRITY_FAILURE", operation);
  }
}

function cancelled(signal: AbortSignal | undefined, error: unknown): boolean {
  return signal?.aborted === true || (typeof DOMException !== "undefined" && error instanceof DOMException && error.name === "AbortError");
}

async function performRead<T>(fetchTransport: FetchTransport, url: string, options: RequestOptions, operation: string, decodeData: (data: unknown) => T): Promise<ReadResult<T>> {
  let response: Response;
  try {
    response = await fetchTransport(url, { method: "GET", cache: "no-store", credentials: "same-origin", signal: options.signal });
  } catch (error) {
    if (cancelled(options.signal, error)) throw new ReadClientError("cancelled", "INTERRUPTED", operation);
    throw new ReadClientError("network", "DEPENDENCY_UNAVAILABLE", operation, true);
  }
  let value: unknown;
  try {
    value = await readJSON(response, operation, options.signal);
  } catch (error) {
    if (cancelled(options.signal, error)) throw new ReadClientError("cancelled", "INTERRUPTED", operation);
    throw error;
  }
  const envelope = decodeReadEnvelope(value, operation);
  if (!response.ok || envelope.status !== "succeeded" || envelope.errors.length !== 0) {
    const failure = envelope.errors[0];
    if (!failure) return mismatch(operation, "failure response has no stable error");
    throw new ReadClientError("api", failure.code, failure.target, failure.retryable, envelope.requestId);
  }
  return { ...envelope, data: decodeData(envelope.data) };
}

async function performChange<T>(fetchTransport: FetchTransport, url: string, request: unknown, options: RequestOptions, operation: string, decodeData: (data: unknown) => T): Promise<ReadResult<T>> {
  let response: Response;
  try {
    response = await fetchTransport(url, {
      method: "POST", cache: "no-store", credentials: "same-origin", signal: options.signal,
      headers: { Accept: "application/json", "Content-Type": "application/json", "X-Vsk-Intent": "explicit" },
      body: JSON.stringify(request),
    });
  } catch (error) {
    if (cancelled(options.signal, error)) throw new ReadClientError("cancelled", "INTERRUPTED", operation);
    throw new ReadClientError("network", "DEPENDENCY_UNAVAILABLE", operation, true);
  }
  const envelope = decodeReadEnvelope(await readJSON(response, operation, options.signal), operation);
  if (!response.ok || envelope.status !== "succeeded" || envelope.errors.length !== 0) {
    const failure = envelope.errors[0];
    if (!failure) return mismatch(operation, "failure response has no stable error");
    throw new ReadClientError("api", failure.code, failure.target, failure.retryable, envelope.requestId);
  }
  return { ...envelope, data: decodeData(envelope.data) };
}

function encodePathString(value: string, name: string): string {
  if (value.length === 0 || value.length > 128) return mismatch(name, "invalid path value");
  return encodeURIComponent(value);
}

function encodePathInteger(value: number, name: string): string {
  if (!Number.isSafeInteger(value) || value < 1) return mismatch(name, "invalid path integer");
  return String(value);
}

function pageQuery(value: ApiPageQuery | undefined): string {
  if (value === undefined) return "";
  const query = decodeApiPageQuery(value);
  const params = new URLSearchParams();
  if (query.limit !== undefined) params.set("limit", String(query.limit));
  if (query.sort !== undefined) params.set("sort", query.sort);
  if (query.cursor !== undefined) params.set("cursor", query.cursor);
  const encoded = params.toString();
  return encoded === "" ? "" : "?" + encoded;
}

function sourceListQuery(value: ApiSourceListQuery | undefined): string {
  if (value === undefined) return "";
  const query = decodeApiSourceListQuery(value);
  const params = new URLSearchParams();
  if (query.limit !== undefined) params.set("limit", String(query.limit));
  if (query.sort !== undefined) params.set("sort", query.sort);
  if (query.cursor !== undefined) params.set("cursor", query.cursor);
  if (query.source !== undefined) params.set("source", query.source);
  if (query.state !== undefined) params.set("state", query.state);
  const encoded = params.toString();
  return encoded === "" ? "" : "?" + encoded;
}

function parseSSEFrame<T>(frame: string, operation: string, eventName: string, decodeData: (data: unknown) => T, eventIdOf: (data: T) => number): T | null {
  const normalized = frame.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  if (normalized === "" || normalized.split("\n").every((line) => line === "" || line.startsWith(":"))) return null;
  let id = "";
  let event = "message";
  const data: string[] = [];
  for (const line of normalized.split("\n")) {
    if (line === "" || line.startsWith(":")) continue;
    const separator = line.indexOf(":");
    const field = separator < 0 ? line : line.slice(0, separator);
    let value = separator < 0 ? "" : line.slice(separator + 1);
    if (value.startsWith(" ")) value = value.slice(1);
    if (field === "id") id = value;
    if (field === "event") event = value;
    if (field === "data") data.push(value);
  }
  if (event !== eventName || !/^[1-9]\d*$/.test(id) || data.length === 0) return mismatch(operation, "invalid event frame");
  const numericId = Number(id);
  if (!Number.isSafeInteger(numericId)) return mismatch(operation, "invalid event identifier");
  let raw: unknown;
  try {
    raw = JSON.parse(data.join("\n"));
  } catch {
    throw new ReadClientError("malformed-json", "INTEGRITY_FAILURE", operation);
  }
  const decoded = decodeData(raw);
  if (eventIdOf(decoded) !== numericId) return mismatch(operation, "event identifier mismatch");
  return decoded;
}

function readStreamChunk(reader: ReadableStreamDefaultReader<Uint8Array>, signal: AbortSignal | undefined, operation: string): Promise<ReadableStreamReadResult<Uint8Array>> {
  if (!signal) return reader.read();
  if (signal.aborted) return Promise.reject(new ReadClientError("cancelled", "INTERRUPTED", operation));
  return new Promise((resolve, reject) => {
    const abort = () => {
      void reader.cancel();
      reject(new ReadClientError("cancelled", "INTERRUPTED", operation));
    };
    signal.addEventListener("abort", abort, { once: true });
    reader.read().then(
      (value) => { signal.removeEventListener("abort", abort); resolve(value); },
      (error) => { signal.removeEventListener("abort", abort); reject(error); },
    );
  });
}

async function* streamSSE<T>(fetchTransport: FetchTransport, url: string, options: StreamOptions, operation: string, eventName: string, decodeData: (data: unknown) => T, eventIdOf: (data: T) => number): AsyncIterable<T> {
  if (options.signal?.aborted) throw new ReadClientError("cancelled", "INTERRUPTED", operation);
  const headers: Record<string, string> = { Accept: "text/event-stream" };
  if (options.lastEventId !== undefined) {
    if (options.lastEventId.length === 0 || options.lastEventId.length > 2048 || /[\r\n]/.test(options.lastEventId)) return mismatch(operation, "invalid last event identifier");
    headers["Last-Event-ID"] = options.lastEventId;
  }
  let response: Response;
  try {
    response = await fetchTransport(url, { method: "GET", cache: "no-store", credentials: "same-origin", headers, signal: options.signal });
  } catch (error) {
    if (cancelled(options.signal, error)) throw new ReadClientError("cancelled", "INTERRUPTED", operation);
    throw new ReadClientError("network", "DEPENDENCY_UNAVAILABLE", operation, true);
  }
  if (!response.ok) {
    const envelope = decodeReadEnvelope(await readJSON(response, operation, options.signal), operation);
    const failure = envelope.errors[0];
    if (!failure) return mismatch(operation, "failure response has no stable error");
    throw new ReadClientError("api", failure.code, failure.target, failure.retryable, envelope.requestId);
  }
  if (!(response.headers.get("content-type") ?? "").toLowerCase().startsWith("text/event-stream") || !response.body) {
    return mismatch(operation, "invalid event stream response");
  }
  const reader = response.body.getReader();
  const decoder = new TextDecoder("utf-8", { fatal: true });
  let buffer = "";
  try {
    for (;;) {
      if (options.signal?.aborted) throw new ReadClientError("cancelled", "INTERRUPTED", operation);
      let next: ReadableStreamReadResult<Uint8Array>;
      try {
        next = await readStreamChunk(reader, options.signal, operation);
      } catch (error) {
        if (cancelled(options.signal, error)) throw new ReadClientError("cancelled", "INTERRUPTED", operation);
        throw new ReadClientError("network", "DEPENDENCY_UNAVAILABLE", operation, true);
      }
      if (next.done) {
        if (options.signal?.aborted) throw new ReadClientError("cancelled", "INTERRUPTED", operation);
        throw new ReadClientError("network", "DEPENDENCY_UNAVAILABLE", operation, true);
      }
      try {
        buffer += decoder.decode(next.value, { stream: true });
      } catch {
        throw new ReadClientError("malformed-json", "INTEGRITY_FAILURE", operation);
      }
      if (buffer.length > 1_048_576) return mismatch(operation, "event frame is too large");
      for (;;) {
        const boundary = /\r\n\r\n|\n\n|\r\r/.exec(buffer);
        if (!boundary || boundary.index === undefined) break;
        const frame = buffer.slice(0, boundary.index);
        buffer = buffer.slice(boundary.index + boundary[0].length);
        const decoded = parseSSEFrame(frame, operation, eventName, decodeData, eventIdOf);
        if (decoded !== null) yield decoded;
      }
    }
  } finally {
    try { await reader.cancel(); } catch { /* stream is already closed */ }
  }
}

`)
	renderFiniteReadClient(&output, endpoints)
	renderChangeClient(&output, endpoints)
	return output.Bytes()
}

func renderFiniteReadClient(output *bytes.Buffer, endpoints []metadata.EndpointDefinition) {
	output.WriteString("export type ReadClient = {\n")
	for _, endpoint := range endpoints {
		if endpoint.Availability != metadata.AvailabilityAvailable || endpoint.Method != "GET" {
			continue
		}
		if endpoint.Stream == metadata.StreamFinite {
			fmt.Fprintf(output, "  readonly %s: %s;\n", browserMethodName(endpoint), browserMethodType(endpoint))
		} else if endpoint.Stream == metadata.StreamSSE {
			fmt.Fprintf(output, "  readonly streamEvents: (options?: StreamOptions) => AsyncIterable<%s>;\n", schemaGoName(endpoint.DataSchema))
		}
	}
	output.WriteString("};\n\nexport function createReadClient(fetchTransport: FetchTransport): ReadClient {\n  return {\n")
	for _, endpoint := range endpoints {
		if endpoint.Availability != metadata.AvailabilityAvailable || endpoint.Method != "GET" {
			continue
		}
		if endpoint.Stream == metadata.StreamFinite {
			renderFiniteMethod(output, endpoint)
		} else if endpoint.Stream == metadata.StreamSSE {
			fmt.Fprintf(output, "    streamEvents(options = {}) {\n      return streamSSE(fetchTransport, %s, options, %s, \"audit-event\", decode%s, (data) => data.event.eventId);\n    },\n", strconv.Quote(endpoint.Path), strconv.Quote(endpoint.ID), schemaGoName(endpoint.DataSchema))
		}
	}
	output.WriteString("  };\n}\n")
}

func renderChangeClient(output *bytes.Buffer, endpoints []metadata.EndpointDefinition) {
	output.WriteString("\nexport type ChangeClient = {\n")
	for _, endpoint := range endpoints {
		if endpoint.OwnerPhase == "4" {
			fmt.Fprintf(output, "  readonly %s: %s;\n", browserMethodName(endpoint), browserMethodType(endpoint))
		}
	}
	output.WriteString("};\n\nexport function createChangeClient(fetchTransport: FetchTransport): ChangeClient {\n  return {\n")
	for _, endpoint := range endpoints {
		if endpoint.OwnerPhase == "4" {
			renderFiniteMethod(output, endpoint)
		}
	}
	output.WriteString("  };\n}\n")
}

func browserMethodType(endpoint metadata.EndpointDefinition) string {
	parameters := browserMethodParameters(endpoint, true)
	return "(" + parameters + ") => Promise<ReadResult<" + schemaGoName(endpoint.DataSchema) + ">>"
}

func browserMethodParameters(endpoint metadata.EndpointDefinition, typed bool) string {
	parts := []string{}
	params := browserPathParameters(endpoint.Path)
	if len(params) != 0 {
		fields := make([]string, len(params))
		for index, name := range params {
			kind := "string"
			if name == "revision" {
				kind = "number"
			}
			fields[index] = "readonly " + name + ": " + kind
		}
		value := "path"
		if typed {
			value += ": { " + strings.Join(fields, "; ") + " }"
		}
		parts = append(parts, value)
	}
	if endpoint.QuerySchema != "" {
		value := "query = {}"
		if typed {
			value = "query?: " + schemaGoName(endpoint.QuerySchema)
		}
		parts = append(parts, value)
	}
	if endpoint.RequestSchema != "" {
		value := "request"
		if typed {
			value += ": " + schemaGoName(endpoint.RequestSchema)
		}
		parts = append(parts, value)
	}
	value := "options = {}"
	if typed {
		value = "options?: RequestOptions"
	}
	parts = append(parts, value)
	return strings.Join(parts, ", ")
}

func renderFiniteMethod(output *bytes.Buffer, endpoint metadata.EndpointDefinition) {
	method := browserMethodName(endpoint)
	fmt.Fprintf(output, "    async %s(%s) {\n", method, browserMethodParameters(endpoint, false))
	fmt.Fprintf(output, "      const operation = %s;\n", strconv.Quote(endpoint.ID))
	pathExpression := strconv.Quote(endpoint.Path)
	for _, name := range browserPathParameters(endpoint.Path) {
		encoder := "encodePathString"
		if name == "revision" {
			encoder = "encodePathInteger"
		}
		pathExpression = strings.Replace(pathExpression, "{"+name+"}", `" + `+encoder+`(path.`+name+`, "`+name+`") + "`, 1)
	}
	if endpoint.QuerySchema != "" {
		queryFunction := "pageQuery"
		if endpoint.QuerySchema == "vegastack-labs.dev/api-source-list-query" {
			queryFunction = "sourceListQuery"
		}
		pathExpression += " + " + queryFunction + "(query)"
	}
	if endpoint.Method == "POST" {
		fmt.Fprintf(output, "      const body = decode%s(request);\n", schemaGoName(endpoint.RequestSchema))
		fmt.Fprintf(output, "      return performChange(fetchTransport, %s, body, options, operation, decode%s);\n", pathExpression, schemaGoName(endpoint.DataSchema))
	} else {
		fmt.Fprintf(output, "      return performRead(fetchTransport, %s, options, operation, decode%s);\n", pathExpression, schemaGoName(endpoint.DataSchema))
	}
	output.WriteString("    },\n")
}

func browserPathParameters(path string) []string {
	parameters := []string{}
	for {
		start := strings.IndexByte(path, '{')
		if start < 0 {
			return parameters
		}
		end := strings.IndexByte(path[start:], '}')
		if end < 0 {
			return parameters
		}
		parameters = append(parameters, path[start+1:start+end])
		path = path[start+end+1:]
	}
}

func browserMethodName(endpoint metadata.EndpointDefinition) string {
	switch endpoint.ID {
	case "api.v1.declarations.revise":
		return "reviseDeclaration"
	case "api.v1.declarations.get":
		return "getDeclaration"
	case "api.v1.plans.create":
		return "createPlan"
	case "api.v1.plans.get":
		return "getPlan"
	case "api.v1.plans.execute":
		return "executePlan"
	case "api.v1.runs.get":
		return "getRun"
	case "api.v1.runs.cancel":
		return "cancelRun"
	case "api.v1.runs.resume":
		return "resumeRun"
	}
	parts := strings.Split(strings.TrimPrefix(endpoint.ID, "api.v1."), ".")
	resource, action := parts[0], parts[len(parts)-1]
	words := strings.Split(resource, "-")
	if action == "get" {
		last := len(words) - 1
		switch words[last] {
		case "drafts", "assets", "nodes", "aliases", "observations":
			words[last] = strings.TrimSuffix(words[last], "s")
			if words[last] == "aliase" {
				words[last] = "alias"
			}
		}
	}
	for index, word := range words {
		words[index] = strings.ToUpper(word[:1]) + word[1:]
	}
	prefix := "get"
	if action == "list" {
		prefix = "list"
	}
	return prefix + strings.Join(words, "")
}

func renderBrowserType(output *bytes.Buffer, schema metadata.SchemaDefinition) {
	fmt.Fprintf(output, "export interface %s {\n", schemaGoName(schema.ID))
	for _, field := range schema.Fields {
		optional := ""
		if !field.Required {
			optional = "?"
		}
		fmt.Fprintf(output, "  readonly %s%s: %s;\n", strconv.Quote(field.JSONName), optional, browserType(field))
	}
	output.WriteString("}\n\n")
}

func browserType(field metadata.FieldDefinition) string {
	var value string
	if len(field.Enum) != 0 {
		parts := make([]string, len(field.Enum))
		for index, enum := range field.Enum {
			parts[index] = strconv.Quote(enum)
		}
		value = strings.Join(parts, " | ")
	} else if field.Ref != "" {
		value = schemaGoName(field.Ref)
	} else {
		switch field.Kind {
		case metadata.ValueString:
			value = "string"
		case metadata.ValueBoolean:
			value = "boolean"
		case metadata.ValueInteger:
			value = "number"
		case metadata.ValueObject:
			value = "Readonly<Record<string, unknown>>"
		case metadata.ValueArray:
			item := "unknown"
			if field.ItemRef != "" {
				item = schemaGoName(field.ItemRef)
			} else {
				switch field.ItemKind {
				case metadata.ValueString:
					item = "string"
				case metadata.ValueBoolean:
					item = "boolean"
				case metadata.ValueInteger:
					item = "number"
				}
			}
			value = "ReadonlyArray<" + item + ">"
		}
	}
	if field.Nullable {
		value += " | null"
	}
	return value
}
