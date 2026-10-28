package main

import (
	"crypto/sha256"
	"fmt"
)

// #302/#303 confine native PTY/process and owned-cgroup operations to these
// exact Linux source files, exercised by the isolated native fixtures. This
// source binding grants no package-wide syscall scope or runtime authority.
// #312 adds only the exact protected-config, Docker/cgroup and namespace-init
// files; siblings and edits retain no x/sys/unix permission.
// #318 adds exact current network-verifier/bridge bytes, retaining historical seals.
func acceptedCINativeUnixFile(relative string, content []byte) bool {
	var expected []string
	switch relative {
	case "internal/runnerbootstrap/config_linux.go":
		expected = []string{"37c308922c9df1e6a08b0c19145c26bdde7ca5fa4d63194657a42c4691d3b765"}
	case "internal/cijobguard/cgroup_linux.go":
		expected = []string{"4e27550b6199855131e45273da6c48b3ef6b1fa6324deb3bbfac35fa1d72c386"}
	case "internal/cijobrunner/config_linux.go":
		expected = []string{"9d70e78c3fce23205607b51b86f8e3ae7037efea7506445f1b95a9e25e0478a4", "00fbc0e4534d8aaada302bcb50d11a3c6a36f04c22c4a40665ea2c18bd33c017"}
	case "internal/cijobrunner/docker_linux.go":
		expected = []string{"46439b3ec134da75f3c45d577f9ec955f89ac2ab64bb7c968dd68dd7d11cbcbe", "e98d761b0dba026da9ab5b0d39eeb301eced8c25c9db39d0d877e88bd6476203", "9eb3ae14d976fc7f88f2c89a59fa510dc765969c4ab6fcdce65bfc17c0b28c79"}
	case "internal/cijobrunner/pid1_linux.go":
		expected = []string{"496ee76035662b0cdcf58ba579b735fdcb779516e61f6afe943fe0b79357552a"}
	case "internal/cijobrunner/bridge_linux.go":
		expected = []string{"81a89d1a559de6ea502e22ee4c546c1fded9a3d0ded03f3aa37a1698ffad909f"}
	case "internal/cijobrunner/network_linux.go":
		expected = []string{"c5b37a4b02d1d60d79b4dbf64b2db6f2d2ce7a30808c0dfe91d27204968d948c", "6e37a34c5ecd030bd18fe24035bd221a5e2f4ba568e58471ffea5d0de37ca417", "946fdef06c71443ff652d495f19c088d202df121d1137b9c562b3056be4cb75a"}
	default:
		return false
	}
	actual := fmt.Sprintf("%x", sha256.Sum256(content))
	for _, hash := range expected {
		if actual == hash {
			return true
		}
	}
	return false
}

// #313 restores only the persisted, currently revalidated run/device actor.
// No other store file or changed bytes gain principal-setting authority.
func reviewedCIActorFile(relative string, content []byte) bool {
	if relative != "internal/store/ci_job_execution.go" {
		return false
	}
	actual := fmt.Sprintf("%x", sha256.Sum256(content))
	return actual == "06322e37edf0c78139e05be7a83d412621f928671ba0b684e6f33b4e2061a8af" || actual == "44880c2c5ee356aee780aa999327755ea672413d281c2e3d24c90495a5713639"
}
