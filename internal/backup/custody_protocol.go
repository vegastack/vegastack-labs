package backup

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"time"
)

const (
	CustodyProtocolVersion = "1.0.0"
	maxCustodyFrameBytes   = 64 << 10
)

// CustodySession is the complete authority carried into one short-lived
// process. The nonce is one-use and bound to all fields; it is not persisted by
// the child and conveys no database or credential authority.
type CustodySession struct {
	ProtocolVersion      string          `json:"protocolVersion"`
	Role                 string          `json:"role"`
	PlanID               string          `json:"planId"`
	PlanDigest           string          `json:"planDigest"`
	RunID                string          `json:"runId"`
	StepID               string          `json:"stepId"`
	LeaseID              string          `json:"leaseId"`
	RepositoryID         string          `json:"repositoryId"`
	RepositoryClass      string          `json:"repositoryClass"`
	GenerationID         string          `json:"generationId,omitempty"`
	OffsiteRepositoryURL string          `json:"offsiteRepositoryUrl,omitempty"`
	PointID              string          `json:"pointId"`
	SourceID             string          `json:"sourceId"`
	SourceRevision       int64           `json:"sourceRevision"`
	RecoveryEpoch        int64           `json:"recoveryEpoch"`
	MaximumExpiresAt     time.Time       `json:"maximumExpiresAt"`
	MaximumObjects       int64           `json:"maximumObjects"`
	MaximumBytes         int64           `json:"maximumBytes"`
	NonceDigest          string          `json:"nonceDigest"`
	WriterLease          *WriterLease    `json:"writerLease,omitempty"`
	ReadLease            *ReadLease      `json:"readLease,omitempty"`
	RetentionLease       *RetentionLease `json:"retentionLease,omitempty"`
}

func (session CustodySession) valid(now time.Time, maximumLifetime time.Duration) bool {
	if session.ProtocolVersion != CustodyProtocolVersion || session.PlanID == "" || session.PlanDigest == "" ||
		session.RunID == "" || session.StepID == "" || session.LeaseID == "" || session.RepositoryID == "" ||
		session.PointID == "" || session.SourceID == "" || session.SourceRevision < 0 || session.RecoveryEpoch < 0 ||
		session.MaximumObjects <= 0 || session.MaximumBytes <= 0 || len(session.NonceDigest) != 71 ||
		!now.Before(session.MaximumExpiresAt) || session.MaximumExpiresAt.Sub(now) > maximumLifetime {
		return false
	}
	if _, err := hex.DecodeString(session.NonceDigest[7:]); err != nil || session.NonceDigest[:7] != "sha256:" {
		return false
	}
	switch session.Role {
	case "writer":
		return session.WriterLease != nil && session.ReadLease == nil && session.RetentionLease == nil && exactWriterSession(session, *session.WriterLease)
	case "verifier":
		return session.ReadLease != nil && session.WriterLease == nil && session.RetentionLease == nil && exactReadSession(session, *session.ReadLease)
	case "offsite-writer":
		return session.WriterLease != nil && session.ReadLease == nil && session.RetentionLease == nil && session.RepositoryClass == "critical-offsite" &&
			validOffsiteToken(session.GenerationID) && validOffsiteRepositoryURL(session.OffsiteRepositoryURL) && exactWriterSession(session, *session.WriterLease)
	case "retention":
		return session.RetentionLease != nil && session.WriterLease == nil && session.ReadLease == nil && exactRetentionSession(session, *session.RetentionLease)
	default:
		return false
	}
}

func exactWriterSession(session CustodySession, lease WriterLease) bool {
	return lease.PlanID == session.PlanID && lease.PlanDigest == session.PlanDigest && lease.RunID == session.RunID &&
		lease.StepID == session.StepID && lease.LeaseID == session.LeaseID && lease.RepositoryID == session.RepositoryID &&
		lease.RepositoryClass == session.RepositoryClass && lease.PointID == session.PointID &&
		lease.SourceRevision == session.SourceRevision && lease.RecoveryEpoch == session.RecoveryEpoch && lease.MaximumExpiresAt.Equal(session.MaximumExpiresAt)
}

func exactReadSession(session CustodySession, lease ReadLease) bool {
	return lease.LeaseID == session.LeaseID && lease.RepositoryID == session.RepositoryID && lease.PointID == session.PointID &&
		lease.RecoveryEpoch == session.RecoveryEpoch && lease.MaximumExpiresAt.Equal(session.MaximumExpiresAt)
}

func exactRetentionSession(session CustodySession, lease RetentionLease) bool {
	return lease.LeaseID == session.LeaseID && lease.RepositoryID == session.RepositoryID &&
		lease.RecoveryEpoch == session.RecoveryEpoch && lease.MaximumExpiresAt.Equal(session.MaximumExpiresAt) &&
		lease.MaxMutations == session.MaximumObjects && lease.MaxMutationBytes == session.MaximumBytes && len(lease.PlannedSnapshotIDs) > 0
}

type custodyFrame struct {
	Type        string          `json:"type"`
	NonceDigest string          `json:"nonceDigest"`
	Payload     json.RawMessage `json:"payload,omitempty"`
	OK          bool            `json:"ok,omitempty"`
	Code        string          `json:"code,omitempty"`
}

func writeCustodyFrame(writer io.Writer, frame custodyFrame) error {
	body, err := json.Marshal(frame)
	if err != nil || len(body) == 0 || len(body) > maxCustodyFrameBytes {
		return errors.New("invalid custody frame")
	}
	var size [4]byte
	size[0], size[1], size[2], size[3] = byte(len(body)>>24), byte(len(body)>>16), byte(len(body)>>8), byte(len(body))
	if _, err := writer.Write(size[:]); err != nil {
		return err
	}
	_, err = writer.Write(body)
	return err
}

func readCustodyFrame(reader io.Reader) (custodyFrame, error) {
	var size [4]byte
	if _, err := io.ReadFull(reader, size[:]); err != nil {
		return custodyFrame{}, err
	}
	length := int(size[0])<<24 | int(size[1])<<16 | int(size[2])<<8 | int(size[3])
	if length <= 0 || length > maxCustodyFrameBytes {
		return custodyFrame{}, errors.New("invalid custody frame length")
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(reader, body); err != nil {
		return custodyFrame{}, err
	}
	var frame custodyFrame
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&frame); err != nil || frame.Type == "" || len(frame.NonceDigest) != 71 {
		return custodyFrame{}, errors.New("invalid custody frame")
	}
	return frame, nil
}

func custodyNonceDigest(nonce []byte) string {
	sum := sha256.Sum256(nonce)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func exactNonce(got, expected string) bool {
	return len(got) == len(expected) && subtle.ConstantTimeCompare([]byte(got), []byte(expected)) == 1
}
