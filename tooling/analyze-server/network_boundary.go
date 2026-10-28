package main

import (
	"crypto/sha256"
	"fmt"
)

// Approved network workflows revalidate durable run/staged actors against current grants.
// These complete source seals authorize only the existing repository context restorations.
func reviewedNetworkActorFile(relative string, content []byte) bool {
	var expected string
	switch relative {
	case "internal/store/network_endpoint_execution.go":
		expected = "16a027991bfda0ae98afa96225d1cd5b51213c88a7e19c1404cedf9fedf87d14"
	case "internal/store/mesh_repository.go":
		expected = "dad3870e42f47867e26ec70aa8883f248e549e2e66ebf09d1c11a77fd0ba8027"
	case "internal/store/ingress_repository.go":
		expected = "550c1308621dff7b41756c15566c440fc03b8c76b98dc285063f185072734866"
	default:
		return false
	}
	actual := fmt.Sprintf("%x", sha256.Sum256(content))
	// #322 adds bounded pilot-evidence preview; the historical ingress seal stays valid.
	if relative == "internal/store/ingress_repository.go" && actual == "c1fe62ddcb7924866f2cef33bfef52232deab77b01bab8074baa1bef2982e1fa" {
		return true
	}
	// #330 adds finite bootstrap receipts while preserving current actor restoration.
	if relative == "internal/store/ingress_repository.go" && actual == "68d01b82eba0752f365188d31a19b8fd061763997323e136e7b49c80bf2da417" {
		return true
	}
	return actual == expected
}

// Only this protected key reader may use Unix descriptors; siblings and edits lose the exception.
func reviewedNetworkPrivateKeyFile(relative string, content []byte) bool {
	return relative == "internal/networkconnect/private_key_unix.go" && fmt.Sprintf("%x", sha256.Sum256(content)) == "d57bc3d95ea922ea2667802c5ebd4139abab3863099fd9aaebe505fdc65ad7a0"
}
