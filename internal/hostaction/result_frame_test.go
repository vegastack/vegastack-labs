package hostaction

import (
	"bufio"
	"bytes"
	"testing"
)

func TestResultFrameBudgetDoesNotWidenAuthorization(t *testing.T) {
	payload := string(bytes.Repeat([]byte("a"), MaximumFrame+1))
	var b bytes.Buffer
	if err := WriteFrame(&b, payload, MaximumResultFrame); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFrame(bufio.NewReaderSize(&b, MaximumResultFrame+2), MaximumResultFrame); err != nil {
		t.Fatal(err)
	}
	b.Reset()
	if err := WriteFrame(&b, payload, MaximumFrame); err == nil {
		t.Fatal("authorization frame budget widened")
	}
	if err := WriteFrame(&b, string(bytes.Repeat([]byte("a"), MaximumResultFrame)), MaximumResultFrame); err == nil {
		t.Fatal("oversized encoded result accepted")
	}
}
