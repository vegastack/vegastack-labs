package debianbaseline

import (
	"bytes"
	"testing"
)

func TestBaselineInputRejectsBroadActions(t *testing.T) {
	for _, raw := range [][]byte{[]byte(`{"disableAppArmor":true}`), []byte(`{"auditAllSyscalls":true}`), bytes.Repeat([]byte("x"), 32769)} {
		if _, e := DecodeInput(raw); e == nil {
			t.Fatal("uncontrolled baseline accepted")
		}
	}
}
