package stateexport

import "context"

type PublishRequest struct {
	ArtifactID    string
	ContentDigest string
	Bytes         []byte
}

type Publication struct {
	Current  CurrentPointer
	Previous *CurrentPointer
	Created  bool
}

type ArtifactStore interface {
	InspectCurrent(context.Context) (*CurrentPointer, error)
	Publish(context.Context, PublishRequest) (Publication, error)
	ReadArtifact(context.Context, string) ([]byte, error)
	RestoreCurrent(context.Context, CurrentPointer, *CurrentPointer) error
}
