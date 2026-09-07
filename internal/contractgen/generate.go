package contractgen

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/format"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/vegastack/vegastack-labs/internal/metadata"
)

const (
	generatedBy             = "go run ./tooling/generate-contracts --write; DO NOT EDIT"
	commandRegistrySchemaID = "vegastack-labs.dev/command-registry"
	runResultSchemaID       = "vegastack-labs.dev/run-result"
	jsonSchemaDialect       = "https://json-schema.org/draft/2020-12/schema"
)

type registryDocument struct {
	GeneratedBy   string                     `json:"generatedBy"`
	Schema        string                     `json:"schema"`
	SchemaVersion string                     `json:"schemaVersion"`
	Commands      []registryCommand          `json:"commands"`
	Errors        []metadata.ErrorDefinition `json:"errors"`
	Exits         []metadata.ExitDefinition  `json:"exits"`
	Schemas       []registrySchema           `json:"schemas"`
}

type registryCommand struct {
	Path          []string                     `json:"path"`
	Summary       string                       `json:"summary"`
	Availability  metadata.Availability        `json:"availability"`
	OwnerPhase    string                       `json:"ownerPhase"`
	Risk          metadata.RiskClass           `json:"risk"`
	Flags         []metadata.FlagDefinition    `json:"flags,omitempty"`
	RequestSchema string                       `json:"requestSchema,omitempty"`
	ResultSchema  string                       `json:"resultSchema,omitempty"`
	Examples      []metadata.ExampleDefinition `json:"examples,omitempty"`
}

type registrySchema struct {
	ID      string `json:"id"`
	Version string `json:"version"`
}

func Generate(registry metadata.Registry) ([]Artifact, error) {
	if err := metadata.Validate(registry); err != nil {
		return nil, err
	}
	registry = normalizedRegistry(registry)

	markdown, err := renderMarkdown(registry)
	if err != nil {
		return nil, err
	}
	goSource, err := renderGo(registry)
	if err != nil {
		return nil, err
	}
	registryJSON, err := renderRegistryJSON(registry)
	if err != nil {
		return nil, err
	}
	registrySchema, err := renderRegistrySchema()
	if err != nil {
		return nil, err
	}
	runSchema, err := renderRunResultSchema(registry)
	if err != nil {
		return nil, err
	}

	return []Artifact{
		{Path: "docs/generated/command-registry.md", Content: markdown},
		{Path: "internal/generated/contracts_gen.go", Content: goSource},
		{Path: "schemas/v1/command-registry.json", Content: registryJSON},
		{Path: "schemas/v1/command-registry.schema.json", Content: registrySchema},
		{Path: "schemas/v1/run-result.schema.json", Content: runSchema},
	}, nil
}

func normalizedRegistry(registry metadata.Registry) metadata.Registry {
	registry.Commands = append([]metadata.CommandDefinition(nil), registry.Commands...)
	for index := range registry.Commands {
		command := &registry.Commands[index]
		command.Path = append([]string(nil), command.Path...)
		command.Flags = append([]metadata.FlagDefinition(nil), command.Flags...)
		for flagIndex := range command.Flags {
			command.Flags[flagIndex].Enum = append([]string(nil), command.Flags[flagIndex].Enum...)
			sort.Strings(command.Flags[flagIndex].Enum)
		}
		sort.Slice(command.Flags, func(left, right int) bool {
			return command.Flags[left].Name < command.Flags[right].Name
		})
		command.Examples = append([]metadata.ExampleDefinition(nil), command.Examples...)
		for exampleIndex := range command.Examples {
			command.Examples[exampleIndex].Arguments = append([]string(nil), command.Examples[exampleIndex].Arguments...)
		}
		sort.Slice(command.Examples, func(left, right int) bool {
			return strings.Join(command.Examples[left].Arguments, "\x00") < strings.Join(command.Examples[right].Arguments, "\x00")
		})
	}
	sort.Slice(registry.Commands, func(left, right int) bool {
		return strings.Join(registry.Commands[left].Path, "\x00") < strings.Join(registry.Commands[right].Path, "\x00")
	})
	registry.Errors = append([]metadata.ErrorDefinition(nil), registry.Errors...)
	sort.Slice(registry.Errors, func(left, right int) bool { return registry.Errors[left].Code < registry.Errors[right].Code })
	registry.Exits = append([]metadata.ExitDefinition(nil), registry.Exits...)
	sort.Slice(registry.Exits, func(left, right int) bool { return registry.Exits[left].Code < registry.Exits[right].Code })
	registry.Schemas = append([]metadata.SchemaDefinition(nil), registry.Schemas...)
	for index := range registry.Schemas {
		registry.Schemas[index].Fields = append([]metadata.FieldDefinition(nil), registry.Schemas[index].Fields...)
	}
	sort.Slice(registry.Schemas, func(left, right int) bool { return registry.Schemas[left].ID < registry.Schemas[right].ID })
	return registry
}

func renderRegistryJSON(registry metadata.Registry) ([]byte, error) {
	document := registryDocument{
		GeneratedBy:   generatedBy,
		Schema:        commandRegistrySchemaID,
		SchemaVersion: registry.SchemaVersion,
		Errors:        registry.Errors,
		Exits:         registry.Exits,
	}
	for _, command := range registry.Commands {
		document.Commands = append(document.Commands, registryCommand{
			Path:          command.Path,
			Summary:       command.Summary,
			Availability:  command.Availability,
			OwnerPhase:    command.OwnerPhase,
			Risk:          command.Risk,
			Flags:         command.Flags,
			RequestSchema: command.RequestSchema,
			ResultSchema:  command.ResultSchema,
			Examples:      command.Examples,
		})
	}
	for _, schema := range registry.Schemas {
		document.Schemas = append(document.Schemas, registrySchema{ID: schema.ID, Version: schema.Version})
	}
	return encodeJSON(document)
}

func renderRegistrySchema() ([]byte, error) {
	stringArray := map[string]any{
		"type": "array", "minItems": 1, "items": map[string]any{"type": "string", "minLength": 1},
	}
	flag := strictObject(
		[]string{"name", "valueName", "required", "repeatable", "summary", "enum"},
		map[string]any{
			"name":       map[string]any{"type": "string", "pattern": "^--[a-z][a-z0-9-]*$"},
			"valueName":  map[string]any{"type": "string", "minLength": 1},
			"required":   map[string]any{"type": "boolean"},
			"repeatable": map[string]any{"type": "boolean"},
			"summary":    map[string]any{"type": "string", "minLength": 1},
			"enum":       map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "uniqueItems": true},
		},
	)
	example := strictObject(
		[]string{"summary", "arguments"},
		map[string]any{
			"summary":   map[string]any{"type": "string", "minLength": 1},
			"arguments": stringArray,
		},
	)
	command := strictObject(
		[]string{"path", "summary", "availability", "ownerPhase", "risk"},
		map[string]any{
			"path":          stringArray,
			"summary":       map[string]any{"type": "string", "minLength": 1},
			"availability":  map[string]any{"type": "string", "enum": []string{"available", "planned"}},
			"ownerPhase":    map[string]any{"type": "string", "pattern": "^[0-9]+$"},
			"risk":          map[string]any{"type": "string", "enum": []string{"read-only", "unassigned"}},
			"flags":         map[string]any{"type": "array", "items": flag},
			"requestSchema": map[string]any{"type": "string", "minLength": 1},
			"resultSchema":  map[string]any{"type": "string", "minLength": 1},
			"examples":      map[string]any{"type": "array", "items": example},
		},
	)
	command["allOf"] = []any{
		map[string]any{
			"if": map[string]any{
				"properties": map[string]any{"availability": map[string]any{"const": "planned"}},
				"required":   []string{"availability"},
			},
			"then": map[string]any{
				"properties": map[string]any{
					"risk":     map[string]any{"const": "unassigned"},
					"flags":    map[string]any{"maxItems": 0},
					"examples": map[string]any{"maxItems": 0},
				},
				"not": map[string]any{
					"anyOf": []any{
						map[string]any{"required": []string{"requestSchema"}},
						map[string]any{"required": []string{"resultSchema"}},
					},
				},
			},
		},
		map[string]any{
			"if": map[string]any{
				"properties": map[string]any{"availability": map[string]any{"const": "available"}},
				"required":   []string{"availability"},
			},
			"then": map[string]any{
				"required": []string{"resultSchema", "examples"},
				"properties": map[string]any{
					"risk":     map[string]any{"const": "read-only"},
					"examples": map[string]any{"minItems": 1},
				},
			},
		},
	}
	errorDefinition := strictObject(
		[]string{"code", "exitCode"},
		map[string]any{
			"code":     map[string]any{"type": "string", "pattern": "^[A-Z][A-Z0-9_]*$"},
			"exitCode": map[string]any{"type": "integer", "enum": []int{2, 3, 4, 5, 6, 7, 8, 9}},
		},
	)
	exitDefinition := strictObject(
		[]string{"code", "meaning"},
		map[string]any{
			"code":    map[string]any{"type": "integer", "enum": []int{0, 2, 3, 4, 5, 6, 7, 8, 9}},
			"meaning": map[string]any{"type": "string", "minLength": 1},
		},
	)
	schemaDefinition := strictObject(
		[]string{"id", "version"},
		map[string]any{
			"id":      map[string]any{"type": "string", "minLength": 1},
			"version": map[string]any{"type": "string", "pattern": "^1\\.[0-9]+\\.[0-9]+$"},
		},
	)
	document := map[string]any{
		"$schema":              jsonSchemaDialect,
		"$id":                  commandRegistrySchemaID,
		"title":                "VegaStack Labs command registry",
		"x-generated-by":       generatedBy,
		"type":                 "object",
		"additionalProperties": false,
		"required":             []string{"generatedBy", "schema", "schemaVersion", "commands", "errors", "exits", "schemas"},
		"properties": map[string]any{
			"generatedBy":   map[string]any{"type": "string", "const": generatedBy},
			"schema":        map[string]any{"type": "string", "const": commandRegistrySchemaID},
			"schemaVersion": map[string]any{"type": "string", "pattern": "^1\\.[0-9]+\\.[0-9]+$"},
			"commands":      map[string]any{"type": "array", "items": command},
			"errors":        map[string]any{"type": "array", "items": errorDefinition},
			"exits":         map[string]any{"type": "array", "items": exitDefinition},
			"schemas":       map[string]any{"type": "array", "items": schemaDefinition},
		},
	}
	return encodeJSON(document)
}

func renderRunResultSchema(registry metadata.Registry) ([]byte, error) {
	definitions := make(map[string]metadata.SchemaDefinition, len(registry.Schemas))
	for _, definition := range registry.Schemas {
		definitions[definition.ID] = definition
	}
	runResult, ok := definitions[runResultSchemaID]
	if !ok {
		return nil, artifactError("GENERATED_SCHEMA_MISSING", "schemas/v1/run-result.schema.json")
	}
	properties, required, err := schemaProperties(runResult, registry.Errors)
	if err != nil {
		return nil, err
	}
	resultError, ok := definitions["vegastack-labs.dev/result-error"]
	if !ok {
		return nil, artifactError("GENERATED_SCHEMA_MISSING", "schemas/v1/run-result.schema.json")
	}
	errorProperties, errorRequired, err := schemaProperties(resultError, registry.Errors)
	if err != nil {
		return nil, err
	}
	document := map[string]any{
		"$schema":              jsonSchemaDialect,
		"$id":                  runResult.ID,
		"title":                "VegaStack Labs run result",
		"x-generated-by":       generatedBy,
		"type":                 "object",
		"additionalProperties": false,
		"required":             required,
		"properties":           properties,
		"$defs": map[string]any{
			"result-error": strictObject(errorRequired, errorProperties),
		},
	}
	return encodeJSON(document)
}

func schemaProperties(definition metadata.SchemaDefinition, errors []metadata.ErrorDefinition) (map[string]any, []string, error) {
	properties := make(map[string]any, len(definition.Fields))
	required := make([]string, 0, len(definition.Fields))
	for _, field := range definition.Fields {
		property := make(map[string]any)
		typeValue := any(string(field.Kind))
		if field.Nullable {
			typeValue = []string{string(field.Kind), "null"}
		}
		property["type"] = typeValue
		if field.Ref != "" {
			delete(property, "type")
			property["$ref"] = "#/$defs/" + schemaShortName(field.Ref)
		}
		if field.ItemRef != "" {
			property["items"] = map[string]any{"$ref": "#/$defs/" + schemaShortName(field.ItemRef)}
		}
		if len(field.Enum) != 0 {
			property["enum"] = field.Enum
		}
		if definition.ID == "vegastack-labs.dev/result-error" && field.JSONName == "code" {
			codes := make([]string, 0, len(errors))
			for _, definition := range errors {
				codes = append(codes, definition.Code)
			}
			property["enum"] = codes
		}
		if field.Kind == metadata.ValueObject {
			property["additionalProperties"] = field.AdditionalProperties
		}
		properties[field.JSONName] = property
		if field.Required {
			required = append(required, field.JSONName)
		}
	}
	return properties, required, nil
}

func renderGo(registry metadata.Registry) ([]byte, error) {
	var output bytes.Buffer
	output.WriteString("// Code generated by go run ./tooling/generate-contracts --write; DO NOT EDIT.\n\n")
	output.WriteString("package generated\n\n")
	output.WriteString("import \"encoding/json\"\n\n")
	fmt.Fprintf(&output, "const (\n\tSchemaMajor = %d\n\tRegistrySchemaVersion = %s\n", metadata.SchemaMajor, strconv.Quote(registry.SchemaVersion))
	for _, definition := range registry.Errors {
		fmt.Fprintf(&output, "\tErrorCode%s = %s\n", errorCodeGoName(definition.Code), strconv.Quote(definition.Code))
	}
	output.WriteString(")\n\n")

	for _, schema := range registry.Schemas {
		fmt.Fprintf(&output, "type %s struct {\n", schemaGoName(schema.ID))
		for _, field := range schema.Fields {
			fmt.Fprintf(&output, "\t%s %s `json:%s`\n", field.GoName, goFieldType(field), strconv.Quote(field.JSONName))
		}
		output.WriteString("}\n\n")
	}

	output.WriteString("type Command struct {\n\tPath []string `json:\"path\"`\n\tSummary string `json:\"summary\"`\n\tAvailability string `json:\"availability\"`\n\tOwnerPhase string `json:\"ownerPhase\"`\n\tRisk string `json:\"risk\"`\n\tFlags []Flag `json:\"flags,omitempty\"`\n\tRequestSchema string `json:\"requestSchema,omitempty\"`\n\tResultSchema string `json:\"resultSchema,omitempty\"`\n\tExamples []Example `json:\"examples,omitempty\"`\n}\n\n")
	output.WriteString("type Flag struct {\n\tName string `json:\"name\"`\n\tValueName string `json:\"valueName\"`\n\tRequired bool `json:\"required\"`\n\tRepeatable bool `json:\"repeatable\"`\n\tSummary string `json:\"summary\"`\n\tEnum []string `json:\"enum\"`\n}\n\n")
	output.WriteString("type Example struct {\n\tSummary string `json:\"summary\"`\n\tArguments []string `json:\"arguments\"`\n}\n\n")
	output.WriteString("var Commands = []Command{\n")
	for _, command := range registry.Commands {
		fmt.Fprintf(&output, "\t{Path: %#v, Summary: %s, Availability: %s, OwnerPhase: %s, Risk: %s", command.Path, strconv.Quote(command.Summary), strconv.Quote(string(command.Availability)), strconv.Quote(command.OwnerPhase), strconv.Quote(string(command.Risk)))
		if len(command.Flags) != 0 {
			output.WriteString(", Flags: []Flag{")
			for _, flag := range command.Flags {
				fmt.Fprintf(&output, "{Name: %s, ValueName: %s, Required: %t, Repeatable: %t, Summary: %s, Enum: %#v},", strconv.Quote(flag.Name), strconv.Quote(flag.ValueName), flag.Required, flag.Repeatable, strconv.Quote(flag.Summary), flag.Enum)
			}
			output.WriteString("}")
		}
		if command.RequestSchema != "" {
			fmt.Fprintf(&output, ", RequestSchema: %s", strconv.Quote(command.RequestSchema))
		}
		if command.ResultSchema != "" {
			fmt.Fprintf(&output, ", ResultSchema: %s", strconv.Quote(command.ResultSchema))
		}
		if len(command.Examples) != 0 {
			output.WriteString(", Examples: []Example{")
			for _, example := range command.Examples {
				fmt.Fprintf(&output, "{Summary: %s, Arguments: %#v},", strconv.Quote(example.Summary), example.Arguments)
			}
			output.WriteString("}")
		}
		output.WriteString("},\n")
	}
	output.WriteString("}\n\n")
	output.WriteString("var ErrorExitCodes = map[string]int{\n")
	for _, definition := range registry.Errors {
		fmt.Fprintf(&output, "\t%s: %d,\n", strconv.Quote(definition.Code), definition.ExitCode)
	}
	output.WriteString("}\n\n")
	output.WriteString("var ExitMeanings = map[int]string{\n")
	for _, definition := range registry.Exits {
		fmt.Fprintf(&output, "\t%d: %s,\n", definition.Code, strconv.Quote(definition.Meaning))
	}
	output.WriteString("}\n")

	formatted, err := format.Source(output.Bytes())
	if err != nil {
		return nil, artifactError("GENERATED_GO_INVALID", "internal/generated/contracts_gen.go")
	}
	return formatted, nil
}

func renderMarkdown(registry metadata.Registry) ([]byte, error) {
	var output bytes.Buffer
	output.WriteString("<!-- Generated by go run ./tooling/generate-contracts --write; DO NOT EDIT. -->\n")
	output.WriteString("# vsk-labs command registry\n\n")
	fmt.Fprintf(&output, "Contract schema: `%s`\n\n", registry.SchemaVersion)
	for _, availability := range []metadata.Availability{metadata.AvailabilityAvailable, metadata.AvailabilityPlanned} {
		heading := "Available commands"
		if availability == metadata.AvailabilityPlanned {
			heading = "Planned commands"
		}
		fmt.Fprintf(&output, "## %s\n\n", heading)
		for _, command := range registry.Commands {
			if command.Availability != availability {
				continue
			}
			fmt.Fprintf(&output, "### `vsk-labs %s`\n\n", strings.Join(command.Path, " "))
			fmt.Fprintf(&output, "%s\n\n", markdownText(command.Summary))
			fmt.Fprintf(&output, "Owner phase: `%s` · risk: `%s` · availability: `%s`\n\n", command.OwnerPhase, command.Risk, command.Availability)
			for _, flag := range command.Flags {
				fmt.Fprintf(&output, "- `%s <%s>` — %s", flag.Name, flag.ValueName, markdownText(flag.Summary))
				if len(flag.Enum) != 0 {
					fmt.Fprintf(&output, " Allowed: `%s`.", strings.Join(flag.Enum, "`, `"))
				}
				output.WriteString("\n")
			}
			if len(command.Flags) != 0 {
				output.WriteString("\n")
			}
			for _, example := range command.Examples {
				fmt.Fprintf(&output, "- %s: `%s`\n", markdownText(example.Summary), strings.Join(append([]string{"vsk-labs"}, example.Arguments...), " "))
			}
			if len(command.Examples) != 0 {
				output.WriteString("\n")
			}
		}
	}
	return output.Bytes(), nil
}

func strictObject(required []string, properties map[string]any) map[string]any {
	return map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"required":             required,
		"properties":           properties,
	}
}

func encodeJSON(value any) ([]byte, error) {
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		return nil, artifactError("GENERATED_JSON_INVALID", "json")
	}
	return output.Bytes(), nil
}

func schemaShortName(identifier string) string {
	parts := strings.Split(identifier, "/")
	return parts[len(parts)-1]
}

func schemaGoName(identifier string) string {
	parts := strings.FieldsFunc(schemaShortName(identifier), func(r rune) bool { return r == '-' || r == '_' })
	for index, part := range parts {
		runes := []rune(part)
		if len(runes) != 0 {
			runes[0] = unicode.ToUpper(runes[0])
		}
		parts[index] = string(runes)
	}
	return strings.Join(parts, "")
}

func errorCodeGoName(code string) string {
	parts := strings.Split(strings.ToLower(code), "_")
	for index, part := range parts {
		if part == "" {
			continue
		}
		parts[index] = strings.ToUpper(part[:1]) + part[1:]
	}
	return strings.Join(parts, "")
}

func goFieldType(field metadata.FieldDefinition) string {
	var fieldType string
	switch field.Kind {
	case metadata.ValueString:
		fieldType = "string"
	case metadata.ValueBoolean:
		fieldType = "bool"
	case metadata.ValueInteger:
		fieldType = "int64"
	case metadata.ValueObject:
		if field.Ref != "" {
			fieldType = schemaGoName(field.Ref)
		} else {
			fieldType = "json.RawMessage"
		}
	case metadata.ValueArray:
		fieldType = "[]" + schemaGoName(field.ItemRef)
	}
	if field.Nullable {
		fieldType = "*" + fieldType
	}
	return fieldType
}

func markdownText(value string) string {
	value = strings.ReplaceAll(value, "|", "\\|")
	value = strings.ReplaceAll(value, "\r", " ")
	return strings.ReplaceAll(value, "\n", " ")
}
