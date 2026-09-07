package metadata

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
)

var (
	commandPartPattern = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
	flagPattern        = regexp.MustCompile(`^--[a-z][a-z0-9-]*$`)
	phasePattern       = regexp.MustCompile(`^[0-9]+$`)
	schemaIDPattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9./-]*$`)
	versionPattern     = regexp.MustCompile(`^1\.[0-9]+\.[0-9]+$`)
	errorCodePattern   = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
)

func Validate(registry Registry) error {
	if !versionPattern.MatchString(registry.SchemaVersion) {
		return validationError("SCHEMA_MAJOR_UNSUPPORTED", "registry.schemaVersion")
	}

	schemas, err := validateSchemas(registry.Schemas)
	if err != nil {
		return err
	}
	if err := validateCommands(registry.Commands, schemas); err != nil {
		return err
	}
	if err := validateErrors(registry.Errors); err != nil {
		return err
	}
	return validateExits(registry.Exits)
}

func validateCommands(commands []CommandDefinition, schemas map[string]struct{}) error {
	if len(commands) == 0 {
		return validationError("METADATA_REQUIRED", "commands")
	}
	seen := make(map[string]struct{}, len(commands))
	for index, command := range commands {
		location := fmt.Sprintf("commands[%d]", index)
		if len(command.Path) == 0 {
			return validationError("METADATA_REQUIRED", location+".path")
		}
		for partIndex, part := range command.Path {
			if !commandPartPattern.MatchString(part) {
				return validationError("METADATA_INVALID", fmt.Sprintf("%s.path[%d]", location, partIndex))
			}
		}
		name := commandName(command.Path)
		if _, ok := seen[name]; ok {
			return validationError("METADATA_DUPLICATE", location+".path")
		}
		seen[name] = struct{}{}
		if command.Summary == "" || command.OwnerPhase == "" {
			return validationError("METADATA_REQUIRED", location)
		}
		if !phasePattern.MatchString(command.OwnerPhase) {
			return validationError("METADATA_INVALID", location+".ownerPhase")
		}

		switch command.Availability {
		case AvailabilityAvailable:
			if command.Risk != RiskReadOnly {
				return validationError("METADATA_INVALID", location+".risk")
			}
			if _, ok := schemas[command.ResultSchema]; !ok {
				return validationError("METADATA_REFERENCE", location+".resultSchema")
			}
			if len(command.Examples) == 0 {
				return validationError("METADATA_REQUIRED", location+".examples")
			}
		case AvailabilityPlanned:
			if command.Risk != RiskUnassigned || len(command.Flags) != 0 || command.RequestSchema != "" || command.ResultSchema != "" || len(command.Examples) != 0 {
				return validationError("PLANNED_COMMAND_DETAIL", location)
			}
		default:
			return validationError("METADATA_INVALID", location+".availability")
		}

		if command.RequestSchema != "" {
			if !safeSchemaID(command.RequestSchema) {
				return validationError("METADATA_PATH_UNSAFE", location+".requestSchema")
			}
			if _, ok := schemas[command.RequestSchema]; !ok {
				return validationError("METADATA_REFERENCE", location+".requestSchema")
			}
		}
		if command.ResultSchema != "" && !safeSchemaID(command.ResultSchema) {
			return validationError("METADATA_PATH_UNSAFE", location+".resultSchema")
		}
		if err := validateFlags(command.Flags, location); err != nil {
			return err
		}
		if err := validateExamples(command, location); err != nil {
			return err
		}
	}
	return nil
}

func validateFlags(flags []FlagDefinition, commandLocation string) error {
	seen := make(map[string]struct{}, len(flags))
	for index, flag := range flags {
		location := fmt.Sprintf("%s.flags[%d]", commandLocation, index)
		if !flagPattern.MatchString(flag.Name) || flag.ValueName == "" || flag.Summary == "" {
			return validationError("METADATA_INVALID", location)
		}
		if _, ok := seen[flag.Name]; ok {
			return validationError("METADATA_DUPLICATE", location+".name")
		}
		seen[flag.Name] = struct{}{}
		if hasDuplicate(flag.Enum) {
			return validationError("METADATA_DUPLICATE", location+".enum")
		}
	}
	return nil
}

func validateExamples(command CommandDefinition, commandLocation string) error {
	for index, example := range command.Examples {
		location := fmt.Sprintf("%s.examples[%d]", commandLocation, index)
		if example.Summary == "" || len(example.Arguments) < len(command.Path) {
			return validationError("METADATA_INVALID", location)
		}
		for argumentIndex, argument := range example.Arguments {
			if argument == "" {
				return validationError("METADATA_INVALID", fmt.Sprintf("%s.arguments[%d]", location, argumentIndex))
			}
		}
		for pathIndex, part := range command.Path {
			if example.Arguments[pathIndex] != part {
				return validationError("METADATA_INVALID", location+".arguments")
			}
		}
	}
	return nil
}

func validateSchemas(definitions []SchemaDefinition) (map[string]struct{}, error) {
	if len(definitions) == 0 {
		return nil, validationError("METADATA_REQUIRED", "schemas")
	}
	schemas := make(map[string]struct{}, len(definitions))
	for index, definition := range definitions {
		location := fmt.Sprintf("schemas[%d]", index)
		if !safeSchemaID(definition.ID) || !versionPattern.MatchString(definition.Version) {
			return nil, validationError("METADATA_INVALID", location)
		}
		if _, ok := schemas[definition.ID]; ok {
			return nil, validationError("METADATA_DUPLICATE", location+".id")
		}
		schemas[definition.ID] = struct{}{}
	}
	for index, definition := range definitions {
		if err := validateFields(definition.Fields, schemas, fmt.Sprintf("schemas[%d]", index)); err != nil {
			return nil, err
		}
	}
	return schemas, nil
}

func validateFields(fields []FieldDefinition, schemas map[string]struct{}, schemaLocation string) error {
	if len(fields) == 0 {
		return validationError("METADATA_REQUIRED", schemaLocation+".fields")
	}
	jsonNames := make(map[string]struct{}, len(fields))
	goNames := make(map[string]struct{}, len(fields))
	for index, field := range fields {
		location := fmt.Sprintf("%s.fields[%d]", schemaLocation, index)
		if field.JSONName == "" || field.GoName == "" || !validKind(field.Kind) {
			return validationError("METADATA_INVALID", location)
		}
		if _, ok := jsonNames[field.JSONName]; ok {
			return validationError("METADATA_DUPLICATE", location+".jsonName")
		}
		if _, ok := goNames[field.GoName]; ok {
			return validationError("METADATA_DUPLICATE", location+".goName")
		}
		jsonNames[field.JSONName] = struct{}{}
		goNames[field.GoName] = struct{}{}
		if field.Ref != "" {
			if field.Kind != ValueObject {
				return validationError("METADATA_INVALID", location+".ref")
			}
			if _, ok := schemas[field.Ref]; !ok {
				return validationError("METADATA_REFERENCE", location+".ref")
			}
		}
		if field.ItemRef != "" {
			if field.Kind != ValueArray {
				return validationError("METADATA_INVALID", location+".itemRef")
			}
			if _, ok := schemas[field.ItemRef]; !ok {
				return validationError("METADATA_REFERENCE", location+".itemRef")
			}
		}
		if field.Kind == ValueArray && field.ItemRef == "" {
			return validationError("METADATA_REQUIRED", location+".itemRef")
		}
		if field.AdditionalProperties && field.Kind != ValueObject {
			return validationError("METADATA_INVALID", location+".additionalProperties")
		}
		if hasDuplicate(field.Enum) {
			return validationError("METADATA_DUPLICATE", location+".enum")
		}
	}
	return nil
}

func validateErrors(errors []ErrorDefinition) error {
	want := make(map[string]int, len(requiredErrors))
	for _, definition := range requiredErrors {
		want[definition.Code] = definition.ExitCode
	}
	seen := make(map[string]struct{}, len(errors))
	for index, definition := range errors {
		location := fmt.Sprintf("errors[%d]", index)
		if !errorCodePattern.MatchString(definition.Code) {
			return validationError("METADATA_INVALID", location+".code")
		}
		if _, ok := seen[definition.Code]; ok {
			return validationError("METADATA_DUPLICATE", location+".code")
		}
		seen[definition.Code] = struct{}{}
		exit, ok := want[definition.Code]
		if !ok || exit != definition.ExitCode {
			return validationError("ERROR_EXIT_MISMATCH", location)
		}
	}
	if len(seen) != len(want) {
		return validationError("ERROR_REGISTRY_INCOMPLETE", "errors")
	}
	return nil
}

func validateExits(exits []ExitDefinition) error {
	want := make(map[int]string, len(requiredExits))
	for _, definition := range requiredExits {
		want[definition.Code] = definition.Meaning
	}
	seen := make(map[int]struct{}, len(exits))
	for index, definition := range exits {
		location := fmt.Sprintf("exits[%d]", index)
		if _, ok := seen[definition.Code]; ok {
			return validationError("METADATA_DUPLICATE", location+".code")
		}
		seen[definition.Code] = struct{}{}
		meaning, ok := want[definition.Code]
		if !ok || definition.Meaning != meaning {
			return validationError("EXIT_REGISTRY_INVALID", location)
		}
	}
	if len(seen) != len(want) {
		return validationError("EXIT_REGISTRY_INCOMPLETE", "exits")
	}
	return nil
}

func validKind(kind ValueKind) bool {
	switch kind {
	case ValueString, ValueBoolean, ValueInteger, ValueObject, ValueArray:
		return true
	default:
		return false
	}
}

func safeSchemaID(identifier string) bool {
	return schemaIDPattern.MatchString(identifier) &&
		!strings.Contains(identifier, "..") &&
		!strings.Contains(identifier, "\\") &&
		!strings.HasPrefix(identifier, "/") &&
		path.Clean(identifier) == identifier
}

func hasDuplicate(values []string) bool {
	copyValues := append([]string(nil), values...)
	sort.Strings(copyValues)
	for index := 1; index < len(copyValues); index++ {
		if copyValues[index] == copyValues[index-1] {
			return true
		}
	}
	return false
}
