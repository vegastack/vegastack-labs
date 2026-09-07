// Package metadata owns the editable source for VegaStack Labs public command
// and machine-output contracts. Generated artifacts must be derived from these
// types and Current rather than edited independently.
package metadata

import "fmt"

const SchemaMajor = 1

type Availability string

const (
	AvailabilityAvailable Availability = "available"
	AvailabilityPlanned   Availability = "planned"
)

type RiskClass string

const (
	RiskReadOnly   RiskClass = "read-only"
	RiskUnassigned RiskClass = "unassigned"
)

type ValueKind string

const (
	ValueString  ValueKind = "string"
	ValueBoolean ValueKind = "boolean"
	ValueInteger ValueKind = "integer"
	ValueObject  ValueKind = "object"
	ValueArray   ValueKind = "array"
)

type Registry struct {
	SchemaVersion string
	Commands      []CommandDefinition
	Errors        []ErrorDefinition
	Exits         []ExitDefinition
	Schemas       []SchemaDefinition
}

type CommandDefinition struct {
	Path          []string
	Summary       string
	Availability  Availability
	OwnerPhase    string
	Risk          RiskClass
	Flags         []FlagDefinition
	RequestSchema string
	ResultSchema  string
	Examples      []ExampleDefinition
}

type FlagDefinition struct {
	Name       string
	ValueName  string
	Required   bool
	Repeatable bool
	Summary    string
	Enum       []string
}

type ExampleDefinition struct {
	Summary   string
	Arguments []string
}

type ErrorDefinition struct {
	Code     string
	ExitCode int
}

type ExitDefinition struct {
	Code    int
	Meaning string
}

type SchemaDefinition struct {
	ID      string
	Version string
	Fields  []FieldDefinition
}

type FieldDefinition struct {
	JSONName             string
	GoName               string
	Kind                 ValueKind
	Required             bool
	Nullable             bool
	Ref                  string
	ItemRef              string
	Enum                 []string
	AdditionalProperties bool
}

type ValidationError struct {
	Code     string
	Location string
}

func (err *ValidationError) Error() string {
	return fmt.Sprintf("%s at %s", err.Code, err.Location)
}

func validationError(code, location string) error {
	return &ValidationError{Code: code, Location: location}
}
