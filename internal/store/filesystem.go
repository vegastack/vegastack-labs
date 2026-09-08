package store

import (
	"context"
	"io"
	"io/fs"
)

type FileIdentity struct {
	Device uint64
	Inode  uint64
	Links  uint64
	UID    uint32
	Mode   fs.FileMode
	Local  bool
}

type FilesystemInspector interface {
	InspectParent(context.Context, string, uint32) (FileIdentity, error)
	CreateDatabase(context.Context, string, uint32) (FileIdentity, error)
	InspectDatabase(context.Context, string, uint32) (FileIdentity, error)
	AcquireWriterLock(context.Context, string, uint32) (io.Closer, error)
	SameFile(FileIdentity, FileIdentity) bool
}

type durabilityFilesystem interface {
	SyncDatabase(context.Context, string, FileIdentity) error
}
