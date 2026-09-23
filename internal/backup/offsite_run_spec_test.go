package backup

import "testing"

func TestExactOffsiteRepositoryBindingRejectsEndpointAndPrefixLookalikes(t *testing.T) {
	endpoint := "https://account.r2.cloudflarestorage.com"
	want := "s3:https://account.r2.cloudflarestorage.com/bucket-a/critical/generation-a"
	if !exactOffsiteRepositoryBinding(want, endpoint, "bucket-a", "critical", "generation-a") {
		t.Fatal("exact repository binding rejected")
	}
	for name, candidate := range map[string]string{
		"host-suffix":    "s3:https://account.r2.cloudflarestorage.com.evil.invalid/bucket-a/critical/generation-a",
		"host-prefix":    "s3:https://evil-account.r2.cloudflarestorage.com/bucket-a/critical/generation-a",
		"userinfo":       "s3:https://account.r2.cloudflarestorage.com@evil.invalid/bucket-a/critical/generation-a",
		"escaped-path":   "s3:https://account.r2.cloudflarestorage.com/bucket-a/critical%2fgeneration-a",
		"alternate-port": "s3:https://account.r2.cloudflarestorage.com:444/bucket-a/critical/generation-a",
		"bucket-suffix":  "s3:https://account.r2.cloudflarestorage.com/bucket-a-evil/critical/generation-a",
		"prefix-suffix":  "s3:https://account.r2.cloudflarestorage.com/bucket-a/critical-evil/generation-a",
		"generation":     "s3:https://account.r2.cloudflarestorage.com/bucket-a/critical/generation-a-evil",
		"query":          want + "?endpoint=https://account.r2.cloudflarestorage.com/bucket-a/critical/generation-a",
		"fragment":       want + "#generation-a",
	} {
		t.Run(name, func(t *testing.T) {
			if exactOffsiteRepositoryBinding(candidate, endpoint, "bucket-a", "critical", "generation-a") {
				t.Fatal("lookalike repository binding accepted")
			}
		})
	}
}
