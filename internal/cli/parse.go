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
	command generated.Command
	output  outputMode
}

func (parsed parsedArguments) commandName() string {
	return commandName(parsed.command.Path)
}

type argumentFailure struct {
	code   string
	target string
}

func parseArguments(args []string) (parsedArguments, *argumentFailure) {
	parsed := parsedArguments{output: outputHuman}
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
		if index+1 >= len(args) || strings.HasPrefix(args[index+1], "--") {
			return parsed, &argumentFailure{code: generated.ErrorCodeInputInvalid, target: "arguments"}
		}
		value := args[index+1]
		if flag.Name == generated.FlagSchemaVersion && value != strconv.Itoa(generated.SchemaMajor) {
			return parsed, &argumentFailure{code: generated.ErrorCodeSchemaUnsupported, target: "schema-version"}
		}
		if !contains(flag.Enum, value) {
			return parsed, &argumentFailure{code: generated.ErrorCodeInputInvalid, target: "arguments"}
		}
		if flag.Name == generated.FlagOutput {
			parsed.output = outputMode(value)
		}
		seen[flag.Name] = true
		index += 2
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
