package metadata

import (
	"reflect"
	"strings"
	"testing"
)

func TestValidateRejectsDuplicateCommandWithoutLeakingMetadata(t *testing.T) {
	t.Parallel()

	secret := "private-canary-must-not-appear"
	registry := Current()
	duplicate := registry.Commands[0]
	duplicate.Summary = secret
	registry.Commands = append(registry.Commands, duplicate)

	err := Validate(registry)
	if err == nil {
		t.Fatal("Validate() error = nil, want duplicate-command error")
	}
	if !strings.Contains(err.Error(), "METADATA_DUPLICATE") {
		t.Fatalf("Validate() error = %q, want stable code", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("Validate() leaked rejected metadata: %q", err)
	}
}

func TestValidateRejectsInvalidRegistries(t *testing.T) {
	t.Parallel()

	tests := map[string]func(*Registry){
		"unsupported major": func(registry *Registry) { registry.SchemaVersion = "2.0.0" },
		"duplicate flag": func(registry *Registry) {
			registry.Commands[0].Flags = append(registry.Commands[0].Flags, registry.Commands[0].Flags[0])
		},
		"duplicate error": func(registry *Registry) {
			registry.Errors = append(registry.Errors, registry.Errors[0])
		},
		"duplicate exit": func(registry *Registry) {
			registry.Exits = append(registry.Exits, registry.Exits[0])
		},
		"duplicate schema": func(registry *Registry) {
			registry.Schemas = append(registry.Schemas, registry.Schemas[0])
		},
		"missing result schema":      func(registry *Registry) { registry.Commands[0].ResultSchema = "missing" },
		"available risk unassigned":  func(registry *Registry) { registry.Commands[0].Risk = RiskUnassigned },
		"available example missing":  func(registry *Registry) { registry.Commands[0].Examples = nil },
		"owner phase is not numeric": func(registry *Registry) { registry.Commands[0].OwnerPhase = "later" },
		"planned has flags": func(registry *Registry) {
			registry.Commands[2].Flags = []FlagDefinition{{Name: "--invented", ValueName: "value", Summary: "Not approved"}}
		},
		"unsafe schema reference": func(registry *Registry) { registry.Commands[0].ResultSchema = "../secret" },
		"error mapping changed":   func(registry *Registry) { registry.Errors[0].ExitCode = 7 },
		"error missing":           func(registry *Registry) { registry.Errors = registry.Errors[1:] },
		"exit missing":            func(registry *Registry) { registry.Exits = registry.Exits[1:] },
		"field duplicate": func(registry *Registry) {
			registry.Schemas[0].Fields = append(registry.Schemas[0].Fields, registry.Schemas[0].Fields[0])
		},
		"field reference missing": func(registry *Registry) { registry.Schemas[0].Fields[0].Ref = "missing" },
	}

	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			registry := Current()
			mutate(&registry)
			if err := Validate(registry); err == nil {
				t.Fatal("Validate() error = nil")
			}
		})
	}
}

func TestMetadataTypesHaveNoProviderOrVendorField(t *testing.T) {
	t.Parallel()

	types := []reflect.Type{
		reflect.TypeFor[Registry](),
		reflect.TypeFor[CommandDefinition](),
		reflect.TypeFor[SchemaDefinition](),
	}
	for _, typ := range types {
		for index := 0; index < typ.NumField(); index++ {
			name := strings.ToLower(typ.Field(index).Name)
			if strings.Contains(name, "provider") || strings.Contains(name, "vendor") {
				t.Fatalf("%s exposes provider-specific field %s", typ, typ.Field(index).Name)
			}
		}
	}
}
