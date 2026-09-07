// Package contractgen renders and verifies checked-in contract artifacts from
// the authoritative metadata graph.
package contractgen

import "fmt"

type Artifact struct {
	Path    string
	Content []byte
}

type ArtifactError struct {
	Code string
	Path string
}

func (err *ArtifactError) Error() string {
	if err.Path == "" {
		return err.Code
	}
	return fmt.Sprintf("%s: %s", err.Code, err.Path)
}

func artifactError(code, artifactPath string) error {
	return &ArtifactError{Code: code, Path: artifactPath}
}
