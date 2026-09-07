package contractgen

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

func Write(root string, artifacts []Artifact) error {
	targets, err := resolveArtifacts(root, artifacts)
	if err != nil {
		return err
	}
	for index, artifact := range artifacts {
		target := targets[index]
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return artifactError("GENERATED_WRITE_FAILED", artifact.Path)
		}
		target, err = secureTarget(root, artifact.Path)
		if err != nil {
			return err
		}
		temporary, err := os.CreateTemp(filepath.Dir(target), ".contracts-*")
		if err != nil {
			return artifactError("GENERATED_WRITE_FAILED", artifact.Path)
		}
		temporaryPath := temporary.Name()
		keepTemporary := true
		defer func() {
			if keepTemporary {
				_ = os.Remove(temporaryPath)
			}
		}()
		if err := temporary.Chmod(0o644); err != nil {
			_ = temporary.Close()
			return artifactError("GENERATED_WRITE_FAILED", artifact.Path)
		}
		if _, err := temporary.Write(artifact.Content); err != nil {
			_ = temporary.Close()
			return artifactError("GENERATED_WRITE_FAILED", artifact.Path)
		}
		if err := temporary.Sync(); err != nil {
			_ = temporary.Close()
			return artifactError("GENERATED_WRITE_FAILED", artifact.Path)
		}
		if err := temporary.Close(); err != nil {
			return artifactError("GENERATED_WRITE_FAILED", artifact.Path)
		}
		if err := os.Rename(temporaryPath, target); err != nil {
			return artifactError("GENERATED_WRITE_FAILED", artifact.Path)
		}
		keepTemporary = false
	}
	return nil
}

func Check(root string, artifacts []Artifact) error {
	targets, err := resolveArtifacts(root, artifacts)
	if err != nil {
		return err
	}
	for index, artifact := range artifacts {
		content, err := os.ReadFile(targets[index])
		if errors.Is(err, os.ErrNotExist) {
			return artifactError("GENERATED_MISSING", artifact.Path)
		}
		if err != nil {
			return artifactError("GENERATED_READ_FAILED", artifact.Path)
		}
		if !bytes.Equal(content, artifact.Content) {
			return artifactError("GENERATED_STALE", artifact.Path)
		}
	}
	return nil
}

func resolveArtifacts(root string, artifacts []Artifact) ([]string, error) {
	if len(artifacts) == 0 {
		return nil, artifactError("GENERATED_ARTIFACTS_EMPTY", "")
	}
	seen := make(map[string]struct{}, len(artifacts))
	targets := make([]string, len(artifacts))
	for index, artifact := range artifacts {
		if _, ok := seen[artifact.Path]; ok {
			return nil, artifactError("GENERATED_PATH_DUPLICATE", artifact.Path)
		}
		seen[artifact.Path] = struct{}{}
		target, err := secureTarget(root, artifact.Path)
		if err != nil {
			return nil, err
		}
		targets[index] = target
	}
	return targets, nil
}

func secureTarget(root, artifactPath string) (string, error) {
	if root == "" || artifactPath == "" || filepath.IsAbs(artifactPath) || strings.Contains(artifactPath, "\\") {
		return "", artifactError("GENERATED_PATH_UNSAFE", artifactPath)
	}
	cleanPath := filepath.Clean(filepath.FromSlash(artifactPath))
	if cleanPath == "." || cleanPath == ".." || strings.HasPrefix(cleanPath, ".."+string(filepath.Separator)) {
		return "", artifactError("GENERATED_PATH_UNSAFE", artifactPath)
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "", artifactError("GENERATED_ROOT_INVALID", "")
	}
	resolvedRoot, err := filepath.EvalSymlinks(absRoot)
	if err != nil {
		return "", artifactError("GENERATED_ROOT_INVALID", "")
	}
	target := filepath.Join(resolvedRoot, cleanPath)
	if !withinRoot(resolvedRoot, target) {
		return "", artifactError("GENERATED_PATH_UNSAFE", artifactPath)
	}

	current := resolvedRoot
	parts := strings.Split(cleanPath, string(filepath.Separator))
	for _, part := range parts {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			break
		}
		if err != nil {
			return "", artifactError("GENERATED_PATH_UNSAFE", artifactPath)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			resolved, err := filepath.EvalSymlinks(current)
			if err != nil || !withinRoot(resolvedRoot, resolved) {
				return "", artifactError("GENERATED_PATH_UNSAFE", artifactPath)
			}
			return "", artifactError("GENERATED_PATH_UNSAFE", artifactPath)
		}
	}
	return target, nil
}

func withinRoot(root, target string) bool {
	relative, err := filepath.Rel(root, target)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) && !filepath.IsAbs(relative)
}
