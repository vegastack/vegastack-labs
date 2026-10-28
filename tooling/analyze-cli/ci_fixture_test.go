package main

import "strings"

// Fixtures copy today's source, so use today's additive seal for the same
// package. Historical maps still retain their original acceptance decisions.
func currentCIEnrollmentFixtureSeals() map[string]hostActionSourceSeal {
	result := map[string]hostActionSourceSeal{}
	packages := map[string]bool{}
	for key, seal := range ciEnrollmentSourceSeals {
		result[key] = seal
		packages[strings.SplitN(key, "|", 2)[0]] = true
	}
	for key := range result {
		relative := strings.SplitN(key, "|", 2)[0]
		for current := range currentCIJobFixtureSeals() {
			if strings.HasPrefix(current, relative+"|") {
				delete(result, key)
				break
			}
		}
	}
	for key, seal := range currentCIJobFixtureSeals() {
		if packages[strings.SplitN(key, "|", 2)[0]] {
			result[key] = seal
		}
	}
	return result
}
func isCurrentCIJobFixturePackage(relative string) bool {
	for key := range currentCIJobFixtureSeals() {
		if strings.HasPrefix(key, relative+"|") {
			return true
		}
	}
	return false
}

// Current source fixtures select the latest exact variant for each package;
// they never rewrite or reinterpret historical production seal maps.
func currentCIJobFixtureSeals() map[string]hostActionSourceSeal {
	result := map[string]hostActionSourceSeal{}
	for _, wave := range []map[string]hostActionSourceSeal{ciJobSourceSeals, ciNetworkSourceSeals, ciDeliverySourceSeals} {
		for key := range result {
			relative := strings.SplitN(key, "|", 2)[0]
			for current := range wave {
				if strings.HasPrefix(current, relative+"|") {
					delete(result, key)
					break
				}
			}
		}
		for key, seal := range wave {
			result[key] = seal
		}
	}
	return result
}
