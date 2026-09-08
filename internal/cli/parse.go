package cli

import (
	"strconv"
	"strings"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

type outputMode string

const (
	outputHuman outputMode = generated.OutputHuman
	outputJSON  outputMode = generated.OutputJSON
)

type parsedArguments struct {
	command  generated.Command
	output   outputMode
	values   map[string][]string
	switches map[string]bool
}

func (parsed parsedArguments) commandName() string {
	return commandName(parsed.command.Path)
}

func (parsed parsedArguments) Values(name string) []string {
	return append([]string(nil), parsed.values[name]...)
}

func (parsed parsedArguments) Value(name string) string {
	values := parsed.values[name]
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func (parsed parsedArguments) Switch(name string) bool {
	return parsed.switches[name]
}

type argumentFailure struct {
	code   string
	target string
}

func parseArguments(args []string) (parsedArguments, *argumentFailure) {
	parsed := parsedArguments{
		output:   outputHuman,
		values:   make(map[string][]string),
		switches: make(map[string]bool),
	}
	command, consumed, ok := matchCommand(args)
	if !ok {
		return parsed, &argumentFailure{code: generated.ErrorCodeInputInvalid, target: "command"}
	}
	parsed.command = command

	flags := make(map[string]generated.Flag, len(command.Flags))
	for _, flag := range command.Flags {
		flags[flag.Name] = flag
	}
	seen := make(map[string]bool, len(flags))
	for index := consumed; index < len(args); {
		flag, ok := flags[args[index]]
		if !ok {
			return parsed, &argumentFailure{code: generated.ErrorCodeInputInvalid, target: "arguments"}
		}
		if seen[flag.Name] && !flag.Repeatable {
			return parsed, &argumentFailure{code: generated.ErrorCodeInputInvalid, target: "arguments"}
		}
		seen[flag.Name] = true
		switch flag.Kind {
		case generated.FlagKindSwitch:
			parsed.switches[flag.Name] = true
			index++
		case generated.FlagKindValue:
			if index+1 >= len(args) || strings.HasPrefix(args[index+1], "--") {
				return parsed, &argumentFailure{code: generated.ErrorCodeInputInvalid, target: "arguments"}
			}
			value := args[index+1]
			if value == "" {
				return parsed, &argumentFailure{code: generated.ErrorCodeInputInvalid, target: "arguments"}
			}
			if flag.Name == generated.FlagSchemaVersion && value != strconv.Itoa(generated.SchemaMajor) {
				return parsed, &argumentFailure{code: generated.ErrorCodeSchemaUnsupported, target: "schema-version"}
			}
			if len(flag.Enum) != 0 && !contains(flag.Enum, value) {
				return parsed, &argumentFailure{code: generated.ErrorCodeInputInvalid, target: "arguments"}
			}
			parsed.values[flag.Name] = append(parsed.values[flag.Name], value)
			if flag.Name == generated.FlagOutput {
				parsed.output = outputMode(value)
			}
			index += 2
		default:
			return parsed, &argumentFailure{code: generated.ErrorCodeIntegrityFailure, target: "command-registry"}
		}
	}

	for _, flag := range command.Flags {
		if flag.Required && !seen[flag.Name] {
			return parsed, &argumentFailure{code: generated.ErrorCodeInputInvalid, target: "arguments"}
		}
	}
	return parsed, nil
}

func matchCommand(args []string) (generated.Command, int, bool) {
	var matched generated.Command
	consumed := 0
	for _, command := range generated.Commands {
		if len(command.Path) <= consumed || len(command.Path) > len(args) {
			continue
		}
		matches := true
		for index, part := range command.Path {
			if args[index] != part {
				matches = false
				break
			}
		}
		if matches {
			matched = command
			consumed = len(command.Path)
		}
	}
	return matched, consumed, consumed != 0
}

func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}
