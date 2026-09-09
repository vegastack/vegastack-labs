package labsinventory

import (
	"math"
	"strconv"
	"time"

	"github.com/vegastack/vegastack-labs/internal/inventory"
)

const decimalGB = int64(1_000_000_000)

func parseDecimalInt64(value string) (int64, bool) {
	if value == "" {
		return 0, false
	}
	for index := 0; index < len(value); index++ {
		if value[index] < '0' || value[index] > '9' {
			return 0, false
		}
	}
	parsed, err := strconv.ParseUint(value, 10, 63)
	if err != nil || parsed > math.MaxInt64 {
		return 0, false
	}
	return int64(parsed), true
}

func parseDecimalGB(value string) (int64, bool) {
	parsed, ok := parseDecimalInt64(value)
	if !ok || parsed > math.MaxInt64/decimalGB {
		return 0, false
	}
	return parsed * decimalGB, true
}

type hardwareField struct {
	column     int
	suffix     string
	kind       string
	unit       string
	capacityGB bool
}

var textHardwareFields = []hardwareField{
	{column: 3, suffix: "manufacturer", kind: "manufacturer"},
	{column: 4, suffix: "model", kind: "model"},
	{column: 5, suffix: "cpu-architecture", kind: "cpu-architecture"},
	{column: 6, suffix: "cpu-model", kind: "cpu-model"},
}

var integerHardwareFields = []hardwareField{
	{column: 7, suffix: "cpu-physical-cores", kind: "cpu-physical-cores", unit: "count"},
	{column: 8, suffix: "cpu-logical-threads", kind: "cpu-logical-threads", unit: "count"},
	{column: 9, suffix: "factory-memory", kind: "memory-capacity", unit: "bytes", capacityGB: true},
	{column: 10, suffix: "factory-ssd", kind: "storage-capacity", unit: "bytes", capacityGB: true},
	{column: 11, suffix: "factory-hdd", kind: "storage-capacity", unit: "bytes", capacityGB: true},
	{column: 12, suffix: "current-memory", kind: "memory-capacity", unit: "bytes", capacityGB: true},
	{column: 13, suffix: "current-ssd", kind: "storage-capacity", unit: "bytes", capacityGB: true},
	{column: 14, suffix: "current-hdd", kind: "storage-capacity", unit: "bytes", capacityGB: true},
}

func mapHardwareRow(record int, row []string, assetID inventory.LocalID, capturedAt time.Time) ([]inventory.DraftObservation, []inventory.DraftHardwareFact, []inventory.FieldProvenance, []inventory.Finding) {
	observations := make([]inventory.DraftObservation, 0, 2)
	if anyNonblank(row[3:12]) {
		observations = append(observations, inventory.DraftObservation{ID: localID(record, "factory-observation"), SubjectID: assetID, Kind: "labs-sheet1-factory", Value: "reported", ObservedAt: capturedAt})
	}
	if anyNonblank(row[12:15]) {
		observations = append(observations, inventory.DraftObservation{ID: localID(record, "current-observation"), SubjectID: assetID, Kind: "labs-sheet1-current", Value: "preferred", ObservedAt: capturedAt})
	}
	facts := make([]inventory.DraftHardwareFact, 0, len(textHardwareFields)+len(integerHardwareFields))
	provenance := make([]inventory.FieldProvenance, 0, len(headerV1))
	findings := make([]inventory.Finding, 0)
	statuses := make([]string, len(headerV1))
	for column, value := range row {
		statuses[column] = "reported"
		if value == "" {
			statuses[column] = "missing"
		} else if row[0] == "quarantined" {
			statuses[column] = "quarantined"
		}
	}
	if row[0] != "" && row[0] != "active" && row[0] != "quarantined" && row[0] != "retired" {
		statuses[0] = "invalid"
	}

	for _, field := range textHardwareFields {
		value := row[field.column]
		if value == "" {
			continue
		}
		factValue := value
		facts = append(facts, inventory.DraftHardwareFact{ID: localID(record, field.suffix), Kind: field.kind, TextValue: &factValue})
	}
	for _, field := range integerHardwareFields {
		value := row[field.column]
		if value == "" {
			continue
		}
		parsed, ok := parseDecimalInt64(value)
		code := "UNSUPPORTED_VALUE"
		if field.capacityGB {
			parsed, ok = parseDecimalGB(value)
			code = "INVALID_CAPACITY"
		}
		if !ok {
			statuses[field.column] = "invalid"
			factID := localID(record, field.suffix)
			findings = append(findings, adapterFinding(code, assetID, "hardwareFacts."+string(factID)+".integerValue", rowLocator(record, headerV1[field.column])))
			continue
		}
		factValue := parsed
		facts = append(facts, inventory.DraftHardwareFact{ID: localID(record, field.suffix), Kind: field.kind, IntegerValue: &factValue, Unit: field.unit})
	}

	for column, field := range headerV1 {
		provenance = append(provenance, sourceProvenance(record, assetID, field, statuses[column], capturedAt))
	}
	return observations, facts, provenance, findings
}

func anyNonblank(values []string) bool {
	for _, value := range values {
		if value != "" {
			return true
		}
	}
	return false
}
