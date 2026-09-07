package main

import (
	"fmt"
	"os"

	"github.com/vegastack/vegastack-labs/internal/contractgen"
	"github.com/vegastack/vegastack-labs/internal/metadata"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(arguments []string) int {
	if len(arguments) != 1 || (arguments[0] != "--write" && arguments[0] != "--check") {
		fmt.Fprintln(os.Stderr, "usage: go run ./tooling/generate-contracts --write|--check")
		return 2
	}
	root, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(os.Stderr, "contract generation failed: working directory unavailable")
		return 1
	}
	artifacts, err := contractgen.Generate(metadata.Current())
	if err != nil {
		fmt.Fprintf(os.Stderr, "contract generation failed: %v\n", err)
		return 1
	}
	if arguments[0] == "--write" {
		err = contractgen.Write(root, artifacts)
	} else {
		err = contractgen.Check(root, artifacts)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "contract generation failed: %v\n", err)
		return 1
	}
	return 0
}
