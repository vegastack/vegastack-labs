//go:build !linux

package backup

func newArtifactLayout(Config) (artifactLayout, error) { return nil, unsupportedError() }
