package store

import (
	"context"
	"errors"
	"testing"
)

type interruptedIdentityFilesystem struct {
	FilesystemInspector
	inspect func(context.Context) (FileIdentity, error)
}

func TestIdentityFailureStillLatchesSafeMode(t *testing.T) {
	for _, inspectErr := range []error{nil, errors.New("unsafe database permissions")} {
		s := &Store{identity: FileIdentity{Inode: 1}, health: Health{Mode: DatabaseReady, MutationEnabled: true}}
		s.filesystem = interruptedIdentityFilesystem{inspect: func(context.Context) (FileIdentity, error) {
			return FileIdentity{Inode: 2}, inspectErr
		}}
		if _, err := s.Health(context.Background()); Code(err) != "INTEGRITY_FAILURE" || s.health.Mode != DatabaseSafeMode || s.health.MutationEnabled {
			t.Fatalf("real identity failure was not blocked: %#v, %v", s.health, err)
		}
	}
}

func (f interruptedIdentityFilesystem) InspectDatabase(ctx context.Context, _ string, _ uint32) (FileIdentity, error) {
	return f.inspect(ctx)
}

func (f interruptedIdentityFilesystem) SameFile(left, right FileIdentity) bool { return left == right }

func TestCancelledIdentityInspectionPreservesDatabaseReadiness(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	identity := FileIdentity{Device: 1, Inode: 2, Links: 1, UID: 988, Mode: 0600, Local: true}
	s := &Store{identity: identity, health: Health{Mode: DatabaseReady, MutationEnabled: true, IntegrityStatus: IntegrityVerified}}
	s.filesystem = interruptedIdentityFilesystem{inspect: func(context.Context) (FileIdentity, error) {
		cancel() // Navigation cancellation arrives while the filesystem check runs.
		return FileIdentity{}, ctx.Err()
	}}
	_, err := s.Health(ctx)
	if Code(err) != "INTERRUPTED" {
		t.Errorf("canceled request returned %q, want INTERRUPTED", Code(err))
	}
	s.filesystem = interruptedIdentityFilesystem{inspect: func(context.Context) (FileIdentity, error) { return identity, nil }}
	health, err := s.Health(context.Background())
	if err != nil || health.Mode != DatabaseReady || !health.MutationEnabled || health.IntegrityStatus != IntegrityVerified {
		t.Fatalf("browser cancellation poisoned subsequent health: %#v, %v", health, err)
	}
}
