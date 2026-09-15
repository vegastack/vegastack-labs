package credentialref

import (
	"bytes"
	"testing"
)

func TestTransientValueOwnsAndClearsControlledBytes(t *testing.T) {
	input := []byte("synthetic-private-canary")
	value, err := NewValue(input)
	if err != nil {
		t.Fatal(err)
	}
	input[0] = 'X'
	alias := value.Bytes()
	if alias[0] == 'X' {
		t.Fatal("value retained caller buffer")
	}
	value.Close()
	if bytes.Count(alias, []byte{0}) != len(alias) {
		t.Fatal("controlled value not overwritten")
	}
	if len(value.Bytes()) != 0 {
		t.Fatal("closed value remained readable")
	}
}
