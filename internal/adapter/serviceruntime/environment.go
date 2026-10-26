package serviceruntime

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
)

type EnvironmentFingerprint struct{ Name, Digest string }

var envName = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,127}$`)

// EnvironmentDigest matches the remote hash of one exact key=value line.
// Plaintext environment values never cross the observation transport.
func EnvironmentDigest(name string, value []byte) string {
	b := append([]byte(name+"="), value...)
	b = append(b, '\n')
	digest := sha256.Sum256(b)
	clear(b)
	return "sha256:" + hex.EncodeToString(digest[:])
}
func environmentCommand(name, id string) string {
	projection := `{{range .Config.Env}}{{if eq (index (split . "=") 0) "` + name + `"}}{{println .}}{{end}}{{end}}`
	return docker + "container inspect --format " + quote(projection) + " " + id + " | /usr/bin/sha256sum"
}
func verifyEnvironment(values []EnvironmentFingerprint, id string, run func(string) ([]byte, error)) error {
	if len(values) > 32 {
		return ErrInput
	}
	seen := map[string]bool{}
	for _, v := range values {
		if !envName.MatchString(v.Name) || !digestRE.MatchString(v.Digest) || seen[v.Name] {
			return ErrInput
		}
		seen[v.Name] = true
		raw, e := run(environmentCommand(v.Name, id))
		if e != nil {
			return e
		}
		fields := strings.Fields(string(raw))
		if len(fields) != 2 || fields[1] != "-" || "sha256:"+fields[0] != v.Digest {
			return ErrIdentity
		}
	}
	return nil
}
