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
	RiskReadOnly     RiskClass = "read-only"
	RiskLocalService RiskClass = "local-service"
	RiskUnassigned   RiskClass = "unassigned"
)

type ValueKind string

const (
	ValueString  ValueKind = "string"
	ValueBoolean ValueKind = "boolean"
	ValueInteger ValueKind = "integer"
	ValueObject  ValueKind = "object"
	ValueArray   ValueKind = "array"
)

type FlagKind string

const (
	FlagValue  FlagKind = "value"
	FlagSwitch FlagKind = "switch"
)

type StreamKind string

const (
	StreamFinite StreamKind = "finite"
	StreamSSE    StreamKind = "sse"
)

type Registry struct {
	SchemaVersion string
	Commands      []CommandDefinition
	Endpoints     []EndpointDefinition
	Errors        []ErrorDefinition
	Exits         []ExitDefinition
	Schemas       []SchemaDefinition
}

type EndpointDefinition struct {
	ID          string     `json:"id"`
	Method      string     `json:"method"`
	Path        string     `json:"path"`
	OwnerPhase  string     `json:"ownerPhase"`
	QuerySchema string     `json:"querySchema,omitempty"`
	DataSchema  string     `json:"dataSchema"`
	Stream      StreamKind `json:"stream"`
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
	DataSchema    string
	Examples      []ExampleDefinition
}

type FlagDefinition struct {
	Name       string   `json:"name"`
	Kind       FlagKind `json:"kind"`
	ValueName  string   `json:"valueName"`
	Required   bool     `json:"required"`
	Repeatable bool     `json:"repeatable"`
	Summary    string   `json:"summary"`
	Enum       []string `json:"enum"`
}

type ExampleDefinition struct {
	Summary   string   `json:"summary"`
	Arguments []string `json:"arguments"`
}

type ErrorDefinition struct {
	Code     string `json:"code"`
	ExitCode int    `json:"exitCode"`
}

type ExitDefinition struct {
	Code    int    `json:"code"`
	Meaning string `json:"meaning"`
}

type SchemaDefinition struct {
	ID           string
	Version      string
	ArtifactPath string
	Fields       []FieldDefinition
}

type FieldDefinition struct {
	JSONName             string
	GoName               string
	Kind                 ValueKind
	Required             bool
	Nullable             bool
	Ref                  string
	ItemRef              string
	ItemKind             ValueKind
	Enum                 []string
	AdditionalProperties bool
	Pattern              string
	MinLength            *int
	MaxLength            *int
	Minimum              *int64
	Maximum              *int64
	MinItems             *int
	MaxItems             *int
	UniqueItems          bool
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
