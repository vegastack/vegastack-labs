// Command fake-restic is a test double for the pinned restic child. It proves
// the sealed password FD reaches the child by reading /proc/self/fd/3, and emits
// a restic-compatible backup --json summary. It never echoes the password to any
// output stream, argument, environment variable or temporary file.
package main

import (
	"fmt"
	"os"
)

func main() {
	// The password must arrive only through the inherited sealed FD 3.
	file := os.NewFile(3, "password")
	if file == nil {
		fmt.Fprintln(os.Stderr, "missing password fd")
		os.Exit(2)
	}
	buffer := make([]byte, 4096)
	n, _ := file.Read(buffer)
	_ = file.Close()
	if n == 0 {
		fmt.Fprintln(os.Stderr, "empty password fd")
		os.Exit(2)
	}
	// Emit a restic-shaped summary. The password bytes are never written out.
	fmt.Println(`{"message_type":"status","percent_done":1}`)
	fmt.Println(`{"message_type":"summary","snapshot_id":"0000000000000000000000000000000000000000000000000000000000000001","total_files_processed":3,"total_bytes_processed":4096}`)
}
