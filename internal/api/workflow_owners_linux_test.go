//go:build linux

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/change"
	"github.com/vegastack/vegastack-labs/internal/debianaccess"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/store"
	"testing"
	"time"
)

func TestStoredWorkflowRequiresNestedSubjectAndProbeOwners(t *testing.T) {
	for _, family := range []string{"volume-recovery", "access"} {
		t.Run(family, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Second)
			f := newRoleAdmissionFixture(t, &now)
			var requests []generated.HostActionRequest
			var ops []generated.PlanOperation
			var id, kind string
			if family == "volume-recovery" {
				snapshot := replacementQualifiedRoleSnapshot(t, now)
				for _, m := range snapshot.Measurements {
					if m.Plan.HostAction != nil && m.Plan.HostAction.ActionID == "debian.volume-recovery.verify" {
						requests = []generated.HostActionRequest{*m.Plan.HostAction}
						break
					}
				}
				if len(requests) != 1 {
					t.Fatal("missing recovery fixture")
				}
				req := requests[0]
				d := hostaction.Digest(req)
				id = hostaction.DraftID(req)
				kind = "host.action"
				ops = []generated.PlanOperation{{Sequence: 1, OperationID: "host-action", OperationType: hostaction.OperationType, AdapterID: hostaction.AdapterID, TargetID: req.HostID, InputDigest: hostaction.Digest("credential manifest"), ArtifactDigest: d}}
			} else {
				ops, requests = admissionAccessSequenceForInput(t, f.input, false)
				seq, err := debianaccess.Sequence(ops, requests)
				if err != nil {
					t.Fatal(err)
				}
				// A separately scoped live witness is not an operation execution host.
				for i := range requests {
					if requests[i].ActionID != "debian.access.probe-source" {
						continue
					}
					var probe generated.AccessProbeInput
					_ = json.Unmarshal([]byte(requests[i].ActionInput), &probe)
					for j := range probe.Cases {
						probe.Cases[j].Witness.HostID = "witness-host"
						probe.Cases[j].Witness.IdentityDigest = hostaction.Digest("witness-host")
					}
					raw, _ := json.Marshal(probe)
					requests[i].ActionInput = string(raw)
					requests[i].ActionInputDigest = hostaction.BytesDigest(raw)
					ops[i].ArtifactDigest = hostaction.Digest(requests[i])
					for j := range seq.ProbeSteps {
						if seq.ProbeSteps[j].OperationID == ops[i].OperationID {
							seq.ProbeSteps[j].DraftDigest = ops[i].ArtifactDigest
							seq.ProbeSteps[j].SpecificationDigest = requests[i].ActionInputDigest
						}
					}
				}
				last := len(requests) - 1
				var confirm generated.AccessConfirmInput
				_ = json.Unmarshal([]byte(requests[last].ActionInput), &confirm)
				confirm.ProbeSpecificationDigest = debianaccess.SequenceSpecificationDigest(seq)
				raw, _ := json.Marshal(confirm)
				requests[last].ActionInput = string(raw)
				requests[last].ActionInputDigest = hostaction.BytesDigest(raw)
				ops[last].ArtifactDigest = hostaction.Digest(requests[last])
				seq, err = debianaccess.Sequence(ops, requests)
				if err != nil {
					t.Fatal(err)
				}
				id = "host-access-" + hostaction.Digest(seq)[7:39]
				kind = "host.access"
			}
			hostIDs := map[string]bool{}
			for _, req := range requests {
				d := hostaction.Digest(req)
				raw, _ := json.Marshal(req)
				f.seed.exec(`INSERT OR IGNORE INTO host_action_drafts VALUES(?,?,?,?,?,?)`, "host-action-"+d[7:39], d, raw, "human-a", req.ExpectedStateRevision, req.RecoveryEpoch)
				hostIDs[req.HostID] = true
			}
			nested := ""
			if family == "volume-recovery" {
				var in generated.VolumeRecoveryInput
				_ = json.Unmarshal([]byte(requests[0].ActionInput), &in)
				nested = in.Binding.HostID
				hostIDs[nested] = true
			} else {
				targets, err := debianaccess.SequenceAuxiliaryTargets(requests)
				if err != nil {
					t.Fatal(err)
				}
				for _, target := range targets {
					hostIDs[target.HostID] = true
					if target.HostID == "witness-host" {
						nested = target.HostID
					}
				}
			}
			if nested == "" {
				t.Fatal("fixture must have a distinct nested owner")
			}
			for host := range hostIDs {
				f.seed.exec(`INSERT OR IGNORE INTO effective_authorization_grants VALUES(?, 'human-a','infrastructure-admin','author','host.action.prepare','host',?,NULL,1,'active','now','now')`, "nested-author-"+host, host)
			}
			rev, err := store.NewPlanRepository(f.authority).CurrentRevision(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			input := generated.DeclarationRevisionRequest{Schema: generated.SchemaIDDeclarationRevisionRequest, SchemaVersion: "1.0.0", DeclarationID: id, DeclarationType: kind, ExpectedRevision: 1, ExpectedStateRevision: rev.StateRevision, RecoveryEpoch: rev.RecoveryEpoch, ReasonDigest: hostaction.Digest(family), Extensions: []generated.ContractExtension{}}
			for _, op := range ops {
				input.Operations = append(input.Operations, generated.DeclarationOperation{Sequence: op.Sequence, OperationID: op.OperationID, OperationType: op.OperationType, AdapterID: op.AdapterID, TargetID: op.TargetID, InputDigest: op.InputDigest, ArtifactDigest: op.ArtifactDigest, Idempotent: op.Idempotent})
			}
			service, err := change.NewService(store.NewDeclarationRepository(f.authority), func() time.Time { return now })
			if err != nil {
				t.Fatal(err)
			}
			doc, err := service.Revise(f.ctx, change.AuthorScope{PrincipalID: "human-a", PrincipalMethod: identity.LocalOSPeerMethod, AgentSessionID: "nested-owner-test"}, input)
			if err != nil {
				t.Fatal("actual writer", err)
			}
			// This dedicated reader has every host except the nested subject/probe.
			f.seed.exec(`INSERT INTO read_principals VALUES('nested-reader','active',1,'now','now')`)
			for host := range hostIDs {
				if host != nested {
					f.seed.exec(`INSERT INTO read_grants VALUES('nested-reader','host.read','host',?,1,'active','now','now')`, host)
				}
			}
			reader := identity.Principal{ID: "nested-reader", Kind: identity.PrincipalHuman, Method: identity.LocalOSPeerMethod}
			target := authorization.ReadTarget{Capability: "declaration.read", ResourceKind: "declaration", ResourceID: fmt.Sprintf("%s:%d", id, doc.Document.Revision)}
			auth := store.NewReadAuthorizer(f.authority)
			if _, err = auth.AuthorizeRead(context.Background(), reader, target); err == nil {
				t.Fatal("stored workflow exposed nested owner")
			}
			f.seed.exec(`INSERT INTO read_grants VALUES('nested-reader','host.read','host',?,1,'active','now','now')`, nested)
			if _, err = auth.AuthorizeRead(context.Background(), reader, target); err != nil {
				t.Fatal("all owners denied", err)
			}
			f.seed.exec(`UPDATE read_grants SET status='revoked' WHERE principal_id='nested-reader' AND resource_id=?`, nested)
			if _, err = auth.AuthorizeRead(context.Background(), reader, target); err == nil {
				t.Fatal("revoked nested owner retained navigation")
			}
			f.seed.exec(`UPDATE effective_authorization_grants SET status='revoked' WHERE principal_id='human-a' AND action='author' AND capability='host.action.prepare' AND resource_id=?`, nested)
			input.ExpectedRevision = 2
			input.ExpectedStateRevision = doc.Document.StateRevision
			if _, err = service.Revise(f.ctx, change.AuthorScope{PrincipalID: "human-a", PrincipalMethod: identity.LocalOSPeerMethod, AgentSessionID: "revoked-nested-owner"}, input); err == nil {
				t.Fatal("writer ignored revoked nested author")
			}
		})
	}
}
