//go:build !linux

package store

import (
	"context"
	"io"
)

type unsupportedFilesystem struct{}

func storePlatformSupported() bool { return false }

func newFilesystemInspector() FilesystemInspector { return unsupportedFilesystem{} }

func unsupportedFilesystemError() error {
	return newStoreError("UNSUPPORTED_PLATFORM", "database-platform", false, nil)
}

func (unsupportedFilesystem) InspectParent(context.Context, string, uint32) (FileIdentity, error) {
	return FileIdentity{}, unsupportedFilesystemError()
}

func (unsupportedFilesystem) CreateDatabase(context.Context, string, uint32) (FileIdentity, error) {
	return FileIdentity{}, unsupportedFilesystemError()
}

func (unsupportedFilesystem) InspectDatabase(context.Context, string, uint32) (FileIdentity, error) {
	return FileIdentity{}, unsupportedFilesystemError()
}

func (unsupportedFilesystem) AcquireWriterLock(context.Context, string, uint32) (io.Closer, error) {
	return nil, unsupportedFilesystemError()
}

func (unsupportedFilesystem) SameFile(FileIdentity, FileIdentity) bool { return false }

func (unsupportedFilesystem) SyncDatabase(context.Context, string, FileIdentity) error {
	return unsupportedFilesystemError()
}
