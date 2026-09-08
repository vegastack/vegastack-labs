package backup

import "context"

type fileIdentity struct {
	device uint64
	inode  uint64
	links  uint64
	uid    uint32
	mode   uint32
}

type stagedGeneration struct {
	id               string
	dir              string
	database         string
	manifest         string
	databaseIdentity fileIdentity
}

type publishedGeneration struct {
	id               string
	dir              string
	database         string
	manifest         string
	databaseIdentity fileIdentity
}

type restoreTarget struct {
	dir      string
	database string
}

type artifactLayout interface {
	BeginGeneration(context.Context, string) (stagedGeneration, error)
	SealDatabase(context.Context, stagedGeneration) (fileIdentity, int64, [32]byte, error)
	WriteManifest(context.Context, stagedGeneration, []byte) error
	Publish(context.Context, stagedGeneration) (publishedGeneration, error)
	OpenPublished(context.Context, string) (publishedGeneration, []byte, error)
	BeginRestore(context.Context, string) (restoreTarget, error)
	SealRestore(context.Context, restoreTarget) (fileIdentity, int64, error)
	RemoveRestore(context.Context, restoreTarget) error
}
