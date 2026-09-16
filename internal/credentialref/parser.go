package credentialref

import "regexp"

// Identifier is an opaque logical reference ID, never a path or provider ID.
type Identifier string

var identifierPattern = regexp.MustCompile(`^[a-z][a-z0-9._:-]{0,127}$`)

func ParseID(raw string) (Identifier, error) {
	if !identifierPattern.MatchString(raw) || raw == "." || raw == ".." {
		return "", newError("INPUT_INVALID", "credential-reference")
	}
	return Identifier(raw), nil
}
