package generated

import (
	"encoding/json"
	"strings"
	"testing"
)

func lifecycleRequestFixture(action string) CredentialLifecycleRequest {
	id := "draft-a"
	prior := "version-prior"
	epoch := int64(1)
	digest := "sha256:" + strings.Repeat("a", 64)
	r := CredentialLifecycleRequest{Schema: SchemaIDCredentialLifecycleRequest, SchemaVersion: "1.3.0", ExpectedStateRevision: 7, RecoveryEpoch: 2, TargetDigest: digest, IdempotencyKey: "request-a", Action: action, ReferenceID: "reference-a", ConsumerIDs: []string{"consumer-a"}, RequiredDeniedConsumerIDs: []string{}, MaterialVersion: "version-a", ResolverID: "native-systemd", TargetID: "target-a"}
	switch action {
	case "credential.stage":
		r.DraftID = &id
	case "credential.activate":
		r.RequiredDeniedConsumerIDs = []string{"consumer-b"}
		r.NativeConsumers = &[]CredentialNativeConsumer{{Schema: SchemaIDCredentialNativeConsumer, SchemaVersion: "1.0.0", ConsumerID: "consumer-a", TargetID: "target-a", HostMachineID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", UnitName: "alpha.service", ServiceUID: 1001, ServiceGID: 1001, ProfileID: "profile-a", RoleID: "role-a"}}
		r.NativeDeniedReaders = &[]CredentialNativeDeniedReader{{Schema: SchemaIDCredentialNativeDeniedReader, SchemaVersion: "1.0.0", ConsumerID: "consumer-b", TargetID: "target-a", HostMachineID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ReaderUID: 2001, ReaderGID: 2001, ProfileID: "profile-a", RoleID: "role-b"}}
	case "credential.rotate":
		r.DraftID = &id
		r.PriorMaterialVersion = &prior
		r.RequiredDeniedConsumerIDs = []string{"consumer-b"}
		r.NativeConsumers = &[]CredentialNativeConsumer{{Schema: SchemaIDCredentialNativeConsumer, SchemaVersion: "1.0.0", ConsumerID: "consumer-a", TargetID: "target-a", HostMachineID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", UnitName: "alpha.service", ServiceUID: 1001, ServiceGID: 1001, ProfileID: "profile-a", RoleID: "role-a"}}
		r.NativeDeniedReaders = &[]CredentialNativeDeniedReader{{Schema: SchemaIDCredentialNativeDeniedReader, SchemaVersion: "1.0.0", ConsumerID: "consumer-b", TargetID: "target-a", HostMachineID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ReaderUID: 2001, ReaderGID: 2001, ProfileID: "profile-a", RoleID: "role-b"}}
	case "credential.revoke":
		r.ConsumerIDs = []string{}
	case "credential.recover":
		r.DraftID = &id
		r.PriorRecoveryEpoch = &epoch
		r.CustodyProofDigest = &digest
		r.FormerControllerFenceDigest = &digest
	}
	return r
}

func TestLifecycleRequestSemanticsAtEveryContractDecode(t *testing.T) {
	for _, action := range []string{"credential.stage", "credential.activate", "credential.rotate", "credential.revoke", "credential.recover"} {
		t.Run(action, func(t *testing.T) {
			valid := lifecycleRequestFixture(action)
			if err := ValidateLifecycleRequestSemantics(valid); err != nil {
				t.Fatalf("valid request: %v", err)
			}
			body, _ := json.Marshal(valid)
			if err := ValidateContractJSON(SchemaIDCredentialLifecycleRequest, body, ContractExact); err != nil {
				t.Fatalf("valid decode: %v", err)
			}
			cases := map[string]func(*CredentialLifecycleRequest){
				"wrong-consumer": func(r *CredentialLifecycleRequest) { r.ConsumerIDs = []string{"../private"} },
				"empty-consumer": func(r *CredentialLifecycleRequest) { r.ConsumerIDs = []string{""} },
				"overlap": func(r *CredentialLifecycleRequest) {
					r.ConsumerIDs = []string{"consumer-a"}
					r.RequiredDeniedConsumerIDs = []string{"consumer-a"}
				},
				"wrong-draft": func(r *CredentialLifecycleRequest) {
					id := "draft-a"
					if r.DraftID == nil {
						r.DraftID = &id
					} else {
						r.DraftID = nil
					}
				},
				"wrong-recovery": func(r *CredentialLifecycleRequest) { epoch := int64(2); r.PriorRecoveryEpoch = &epoch },
				"wrong-prior": func(r *CredentialLifecycleRequest) {
					id := "version-a"
					if r.PriorMaterialVersion == nil {
						r.PriorMaterialVersion = &id
					} else {
						r.PriorMaterialVersion = nil
					}
				},
			}
			for name, mutate := range cases {
				t.Run(name, func(t *testing.T) {
					r := valid
					mutate(&r)
					if ValidateLifecycleRequestSemantics(r) == nil {
						t.Fatal("action-invalid request accepted")
					}
					body, _ := json.Marshal(r)
					if ValidateContractJSON(SchemaIDCredentialLifecycleRequest, body, ContractExact) == nil {
						t.Fatal("decode accepted action-invalid request")
					}
				})
			}
		})
	}
}
