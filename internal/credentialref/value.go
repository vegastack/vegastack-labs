package credentialref

import "runtime"

// Value is a short-lived, app-owned byte buffer for one credential-bearing
// adapter call. Bytes must never be placed in a plan, operation, audit record,
// log, process argument, environment variable, or persistent store.
type Value struct{ bytes []byte }

func NewValue(input []byte) (*Value, error) {
	if len(input) == 0 || len(input) > 4096 {
		return nil, &Error{Code: "INPUT_INVALID", Target: "credential-value"}
	}
	owned := append([]byte(nil), input...)
	return &Value{bytes: owned}, nil
}

// Bytes exposes a borrowed alias only while the Value remains open. The
// caller must not retain or copy it after the adapter call ends.
func (value *Value) Bytes() []byte {
	if value == nil {
		return nil
	}
	return value.bytes
}

func (value *Value) Close() {
	if value == nil {
		return
	}
	for index := range value.bytes {
		value.bytes[index] = 0
	}
	runtime.KeepAlive(value.bytes)
	value.bytes = nil
}
