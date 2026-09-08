package inventory

import (
	"net/url"
	"strings"
	"unicode"
)

var secretPrefixes = []string{
	"github_pat_", "ghp_", "gho_", "ghu_", "ghs_", "glpat-", "xoxb-", "xoxp-", "akia",
}

func containsSecretValue(value string) bool {
	lower := strings.ToLower(value)
	if strings.Contains(lower, "-----begin private key-----") || strings.Contains(lower, "-----begin rsa private key-----") || strings.Contains(lower, "-----begin openssh private key-----") {
		return true
	}
	trimmed := strings.TrimSpace(lower)
	for _, prefix := range secretPrefixes {
		if strings.HasPrefix(trimmed, prefix) {
			return true
		}
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return true
		}
	}
	parsed, err := url.Parse(value)
	if err == nil && parsed.IsAbs() && parsed.User != nil {
		if _, present := parsed.User.Password(); present {
			return true
		}
	}
	return false
}

func secretSemanticName(value string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(value, "_", "-"), ".", "-"))
	for _, word := range []string{"password", "passwd", "secret", "credential", "private-key", "access-token", "api-token"} {
		if strings.Contains(normalized, word) {
			return true
		}
	}
	return false
}
