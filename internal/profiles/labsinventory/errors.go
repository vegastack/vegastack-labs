package labsinventory

import "fmt"

const (
	ErrorCSVEmpty             = "CSV_EMPTY"
	ErrorCSVLimitExceeded     = "CSV_LIMIT_EXCEEDED"
	ErrorCSVUTF8Invalid       = "CSV_UTF8_INVALID"
	ErrorCSVMalformed         = "CSV_MALFORMED"
	ErrorCSVHeaderDuplicate   = "CSV_HEADER_DUPLICATE"
	ErrorCSVHeaderMissing     = "CSV_HEADER_MISSING"
	ErrorCSVHeaderUnknown     = "CSV_HEADER_UNKNOWN"
	ErrorCSVHeaderOrder       = "CSV_HEADER_ORDER"
	ErrorCSVFormulaProhibited = "CSV_FORMULA_PROHIBITED"
	ErrorCSVControlProhibited = "CSV_CONTROL_PROHIBITED"
	ErrorInterrupted          = "INTERRUPTED"
)

// DecodeError reports only stable classification and safe positions. It never
// includes a header name, cell value, source path, or parser error string.
type DecodeError struct {
	Code   string
	Record int
	Column int
	Field  string
}

func (err *DecodeError) Error() string {
	if err == nil {
		return "CSV_MALFORMED"
	}
	message := err.Code
	if err.Record > 0 {
		message += fmt.Sprintf(": record=%d", err.Record)
	}
	if err.Column > 0 {
		message += fmt.Sprintf(" column=%d", err.Column)
	}
	if err.Field != "" {
		message += " field=" + err.Field
	}
	return message
}

func decodeError(code string, record, column int, field string) error {
	return &DecodeError{Code: code, Record: record, Column: column, Field: field}
}
