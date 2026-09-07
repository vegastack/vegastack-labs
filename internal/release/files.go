package release

import (
	"context"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

const (
	maxManifestBytes  = int64(1 << 20)
	maxPolicyBytes    = int64(1 << 20)
	maxBundleBytes    = int64(4 << 20)
	maxArtifactBytes  = int64(8) << 30
	maxReferenceBytes = 1024
)

type fileSnapshot struct {
	root       *os.Root
	relative   string
	openedInfo os.FileInfo
	size       int64
	mode       os.FileMode
	modTime    time.Time
	target     string
	ownsRoot   bool
}

func openExplicit(filePath, target string, maximum int64) (*os.Root, *os.File, fileSnapshot, string, string, error) {
	if filePath == "" || strings.ContainsRune(filePath, '\x00') {
		return nil, nil, fileSnapshot{}, "", "", newError(generated.ErrorCodeInputInvalid, target)
	}
	absolute, err := filepath.Abs(filePath)
	if err != nil {
		return nil, nil, fileSnapshot{}, "", "", newError(generated.ErrorCodeInputInvalid, target)
	}
	directory, base := filepath.Dir(absolute), filepath.Base(absolute)
	if base == "." || base == string(filepath.Separator) || base == "" {
		return nil, nil, fileSnapshot{}, "", "", newError(generated.ErrorCodeInputInvalid, target)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, nil, fileSnapshot{}, "", "", newError(generated.ErrorCodePrerequisiteBlocked, target)
	}
	info, err := root.Lstat(base)
	if err != nil {
		_ = root.Close()
		if os.IsNotExist(err) || os.IsPermission(err) {
			return nil, nil, fileSnapshot{}, "", "", newError(generated.ErrorCodePrerequisiteBlocked, target)
		}
		return nil, nil, fileSnapshot{}, "", "", newError(generated.ErrorCodeEvidenceInvalid, target+"-file")
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		_ = root.Close()
		return nil, nil, fileSnapshot{}, "", "", newError(generated.ErrorCodeEvidenceInvalid, target+"-file")
	}
	if info.Size() < 0 || info.Size() > maximum {
		_ = root.Close()
		return nil, nil, fileSnapshot{}, "", "", newError(generated.ErrorCodeInputInvalid, target)
	}
	file, err := root.Open(base)
	if err != nil {
		_ = root.Close()
		if os.IsNotExist(err) || os.IsPermission(err) {
			return nil, nil, fileSnapshot{}, "", "", newError(generated.ErrorCodePrerequisiteBlocked, target)
		}
		return nil, nil, fileSnapshot{}, "", "", newError(generated.ErrorCodeEvidenceInvalid, target+"-file")
	}
	openedInfo, err := file.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
		_ = file.Close()
		_ = root.Close()
		return nil, nil, fileSnapshot{}, "", "", newError(generated.ErrorCodeEvidenceInvalid, target+"-file")
	}
	if openedInfo.Size() < 0 || openedInfo.Size() > maximum {
		_ = file.Close()
		_ = root.Close()
		return nil, nil, fileSnapshot{}, "", "", newError(generated.ErrorCodeInputInvalid, target)
	}
	snapshot := fileSnapshot{
		root: root, relative: base, openedInfo: openedInfo, size: openedInfo.Size(),
		mode: openedInfo.Mode(), modTime: openedInfo.ModTime(), target: target + "-file",
	}
	return root, file, snapshot, directory, absolute, nil
}

// openRelative retains the Plan v1 helper seam for focused filesystem tests.
// Long-lived operations use openRelativeRoot with the manifest's retained root.
func openRelative(rootPath, relative string, declaredSize *int64) (*os.File, fileSnapshot, error) {
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return nil, fileSnapshot{}, newError(generated.ErrorCodePrerequisiteBlocked, targetReference)
	}
	maximum := maxBundleBytes
	target := targetBundleFile
	if declaredSize != nil {
		maximum = maxArtifactBytes
		target = targetAssetFile
	}
	file, snapshot, err := openRootFile(root, relative, declaredSize, maximum, target, true)
	if err != nil {
		_ = root.Close()
		return nil, fileSnapshot{}, err
	}
	return file, snapshot, nil
}

func openRelativeRoot(root *os.Root, relative string, declaredSize *int64, maximum int64, target string) (*os.File, fileSnapshot, error) {
	return openRootFile(root, relative, declaredSize, maximum, target, false)
}

func openRootFile(root *os.Root, relative string, declaredSize *int64, maximum int64, target string, ownsRoot bool) (*os.File, fileSnapshot, error) {
	if root == nil {
		return nil, fileSnapshot{}, newError(generated.ErrorCodeInputInvalid, target)
	}
	converted, err := portableReference(relative)
	if err != nil {
		return nil, fileSnapshot{}, err
	}
	info, err := lstatComponents(root, converted, target)
	if err != nil {
		return nil, fileSnapshot{}, err
	}
	if !info.Mode().IsRegular() {
		return nil, fileSnapshot{}, newError(generated.ErrorCodeEvidenceInvalid, target)
	}
	file, err := root.Open(converted)
	if err != nil {
		if os.IsNotExist(err) || os.IsPermission(err) {
			return nil, fileSnapshot{}, newError(generated.ErrorCodePrerequisiteBlocked, target)
		}
		return nil, fileSnapshot{}, newError(generated.ErrorCodeEvidenceInvalid, target)
	}
	openedInfo, err := file.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
		_ = file.Close()
		return nil, fileSnapshot{}, newError(generated.ErrorCodeEvidenceInvalid, target)
	}
	if openedInfo.Size() < 0 || openedInfo.Size() > maximum {
		_ = file.Close()
		return nil, fileSnapshot{}, newError(generated.ErrorCodeInputInvalid, target)
	}
	if declaredSize != nil && (*declaredSize <= 0 || *declaredSize > maximum || openedInfo.Size() != *declaredSize) {
		_ = file.Close()
		return nil, fileSnapshot{}, newError(generated.ErrorCodeEvidenceInvalid, target)
	}
	return file, fileSnapshot{
		root: root, relative: converted, openedInfo: openedInfo, size: openedInfo.Size(),
		mode: openedInfo.Mode(), modTime: openedInfo.ModTime(), target: target, ownsRoot: ownsRoot,
	}, nil
}

func finishFile(file *os.File, snapshot fileSnapshot) error {
	if file == nil || snapshot.root == nil || snapshot.openedInfo == nil {
		return newError(generated.ErrorCodeInputInvalid, snapshot.target)
	}
	var result error
	after, err := file.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(snapshot.openedInfo, after) ||
		after.Size() != snapshot.size || after.Mode() != snapshot.mode || !after.ModTime().Equal(snapshot.modTime) {
		result = newError(generated.ErrorCodeEvidenceInvalid, snapshot.target)
	}
	pathInfo, pathErr := lstatComponents(snapshot.root, snapshot.relative, snapshot.target)
	if pathErr != nil || !pathInfo.Mode().IsRegular() || !os.SameFile(snapshot.openedInfo, pathInfo) {
		result = newError(generated.ErrorCodeEvidenceInvalid, snapshot.target)
	}
	if err := file.Close(); err != nil {
		result = newError(generated.ErrorCodeEvidenceInvalid, snapshot.target)
	}
	if snapshot.ownsRoot {
		if err := snapshot.root.Close(); err != nil {
			result = newError(generated.ErrorCodeEvidenceInvalid, snapshot.target)
		}
	}
	return result
}

func lstatComponents(root *os.Root, relative, target string) (os.FileInfo, error) {
	parts := strings.Split(relative, string(filepath.Separator))
	current := ""
	var info os.FileInfo
	for index, part := range parts {
		if current == "" {
			current = part
		} else {
			current = filepath.Join(current, part)
		}
		var err error
		info, err = root.Lstat(current)
		if err != nil {
			if os.IsNotExist(err) || os.IsPermission(err) {
				return nil, newError(generated.ErrorCodePrerequisiteBlocked, target)
			}
			return nil, newError(generated.ErrorCodeEvidenceInvalid, target)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, newError(generated.ErrorCodeEvidenceInvalid, target)
		}
		if index < len(parts)-1 && !info.IsDir() {
			return nil, newError(generated.ErrorCodeEvidenceInvalid, target)
		}
	}
	return info, nil
}

func portableReference(value string) (string, error) {
	if len(value) == 0 || len(value) > maxReferenceBytes || !isASCII(value) || strings.ContainsAny(value, "\\:\x00") ||
		strings.HasPrefix(value, "/") || path.IsAbs(value) || path.Clean(value) != value {
		return "", newError(generated.ErrorCodeInputInvalid, targetReference)
	}
	parts := strings.Split(value, "/")
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || strings.HasSuffix(part, ".") || strings.HasSuffix(part, " ") ||
			!portableSegment(part) || windowsReservedName(part) {
			return "", newError(generated.ErrorCodeInputInvalid, targetReference)
		}
	}
	converted := filepath.FromSlash(value)
	if filepath.IsAbs(converted) || filepath.VolumeName(converted) != "" || filepath.Clean(converted) != converted {
		return "", newError(generated.ErrorCodeInputInvalid, targetReference)
	}
	return converted, nil
}

func portableSegment(value string) bool {
	for index := 0; index < len(value); index++ {
		character := value[index]
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '.' || character == '_' || character == '-' {
			continue
		}
		return false
	}
	first := value[0]
	return (first >= 'a' && first <= 'z') || (first >= 'A' && first <= 'Z') || (first >= '0' && first <= '9')
}

func windowsReservedName(segment string) bool {
	base := segment
	if dot := strings.IndexByte(base, '.'); dot >= 0 {
		base = base[:dot]
	}
	base = strings.ToUpper(base)
	switch base {
	case "CON", "PRN", "AUX", "NUL":
		return true
	}
	return len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) && base[3] >= '1' && base[3] <= '9'
}

func isASCII(value string) bool {
	for index := 0; index < len(value); index++ {
		if value[index] > 0x7f || value[index] < 0x20 || value[index] == 0x7f {
			return false
		}
	}
	return true
}

func readBounded(ctx context.Context, file *os.File, maximum int64, target string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, interrupted()
	}
	content := make([]byte, 0, min(maximum, 64<<10))
	buffer := make([]byte, 32<<10)
	limited := io.LimitReader(file, maximum+1)
	for {
		if err := ctx.Err(); err != nil {
			return nil, interrupted()
		}
		count, err := limited.Read(buffer)
		if count > 0 {
			content = append(content, buffer[:count]...)
			if int64(len(content)) > maximum {
				return nil, newError(generated.ErrorCodeInputInvalid, target)
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, newError(generated.ErrorCodeEvidenceInvalid, target)
		}
	}
	return content, nil
}
