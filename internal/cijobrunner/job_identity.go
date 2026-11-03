package cijobrunner

import (
	"encoding/json"
	"os"
	"strconv"

	"github.com/vegastack/vegastack-labs/internal/cijobguard"
)

const jobIdentityFilename = ".vsk-ci-job.json"

// writeJobIdentity publishes only public provider assignment metadata, after the
// hook has consumed its exact allow. Job code can alter its own files: this is
// packaging input, never admission or publication authority. The controller must
// still verify the real provider assignment independently.
func writeJobIdentity(directory string, b cijobguard.Binding) error {
	for _, id := range []string{b.RunID, b.JobID} {
		n, err := strconv.ParseInt(id, 10, 64)
		if err != nil || n < 1 || strconv.FormatInt(n, 10) != id {
			return ErrProtocol
		}
	}
	if b.Attempt == 0 {
		return ErrProtocol
	}
	raw, err := json.Marshal(struct {
		RunID   string `json:"runId"`
		JobID   string `json:"jobId"`
		Attempt uint32 `json:"attempt"`
	}{b.RunID, b.JobID, b.Attempt})
	if err != nil {
		return ErrProtocol
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return ErrBlocked
	}
	defer root.Close()
	file, err := root.OpenFile(jobIdentityFilename, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return ErrBlocked
	}
	_, writeErr := file.Write(append(raw, '\n'))
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		return ErrBlocked
	}
	return nil
}
