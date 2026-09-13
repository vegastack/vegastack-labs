# Development phase 4 — Declarations, plans, authorization, and execution

Status: implemented; awaiting exact-commit operator acceptance. Issues 4.1 through 4.9 are merged on `main` at `454472328e22cd09e23640f27942e25a6856c2e9`. Issue 4.10 (#67) owns the clean exact-commit acceptance proof and presents the integrated result for an explicit operator decision. Neither a merge nor a green check accepts Phase 4 automatically.

## Outcome and authority boundary

Phase 4 adds provider-neutral inert declaration revisions, immutable canonical plans, current effective authorization, Slack-only human acknowledgement, durable central and external execution, and one shared CLI/Console change workflow. The server remains the only SQLite writer and the only authority that can authorize or execute a plan. The browser, CLI, agents, Slack and adapters cannot grant themselves authority.

The complete software evidence is credential-free and uses isolated synthetic fixtures. It does not contact a live Slack workspace, provider, host, deployment, release system or inventory fleet, and it does not satisfy a deployment gate.

## Fixed behavior

- Saving a declaration creates an inert revision. It performs no provider, host, network or secret-resolution action.
- Planning rechecks current facts, revisions and recovery epoch, then stores one immutable readable and JSON plan with the same digest, targets, operations, risk and expiry.
- Every plan expires after 30 minutes. Changed facts, revisions, epoch or intent make the old plan unusable.
- Human acknowledgement and exact preauthorization are mutually exclusive policy branches. Production-like work always requires the assigned human.
- Slack is a typed acknowledgement transport only. A verified action is bound to one workspace, human, action, plan digest, target, reason and capability, and its proof is consumed once.
- Durable runs persist state before and after effects. Duplicate submission, cancellation, interruption, ambiguous receipts and restart produce explicit safe results rather than repeated or assumed work.
- An external worker receives only one exact target/step binding for at most 60 seconds and checks in every 20 seconds. Lease loss requires recovery; it never silently reassigns ambiguous work.
- CLI and Console use the generated API and show the same plan. The browser has no acknowledgement proof, executor, provider, arbitrary URL or SQLite path.

## Issue index and integrated result

| Phase issue | Outcome | Pull request | Integrated commit |
|---|---|---|---|
| [4.1 (#66)](https://github.com/vegastack/vegastack-labs/issues/66) | Generated declaration, plan, authorization, acknowledgement and run contracts | [#87](https://github.com/vegastack/vegastack-labs/pull/87) | `5c49630efa10cd977414b6f5e671aa61d5233e5d` |
| [4.2 (#76)](https://github.com/vegastack/vegastack-labs/issues/76) | Revisioned inert declarations and immutable plans | [#88](https://github.com/vegastack/vegastack-labs/pull/88) | `f679edbc1fbdf7f0bf8b3069f2c104b972bbcb19` |
| [4.3 (#71)](https://github.com/vegastack/vegastack-labs/issues/71) | Effective authorization and exact risk policy | [#89](https://github.com/vegastack/vegastack-labs/pull/89) | `c80273a8efa33fbce8bd8ec4d0c7ca5106ab43fb` |
| [4.4 (#77)](https://github.com/vegastack/vegastack-labs/issues/77) | Slack human acknowledgement and replay denial | [#92](https://github.com/vegastack/vegastack-labs/pull/92) | `b1665d53ef8fcab0142b0e0702c7567616e8f093` |
| [4.5 (#74)](https://github.com/vegastack/vegastack-labs/issues/74) | Durable plan runs, cancellation and recovery | [#93](https://github.com/vegastack/vegastack-labs/pull/93) | `26aeb9c8e76e043ec23d6ddaf7d3bd6b09070a32` |
| [4.6 (#69)](https://github.com/vegastack/vegastack-labs/issues/69) | Exact external-executor leases and receipts | [#94](https://github.com/vegastack/vegastack-labs/pull/94) | `deaf70d72a1dc3b79155a4397c3904866ae81121` |
| [4.7 (#78)](https://github.com/vegastack/vegastack-labs/issues/78) | CLI plan, apply and durable-run workflows | [#95](https://github.com/vegastack/vegastack-labs/pull/95) | `722bcb4aa4fc04cc4ba03f43ee87d1308a893953` |
| [4.8 (#79)](https://github.com/vegastack/vegastack-labs/issues/79) | Console declaration, plan, approval and run views | [#96](https://github.com/vegastack/vegastack-labs/pull/96), [#97](https://github.com/vegastack/vegastack-labs/pull/97), [#98](https://github.com/vegastack/vegastack-labs/pull/98) | `67295d0698691517249883932029fa0523de2076` |
| [4.9 (#80)](https://github.com/vegastack/vegastack-labs/issues/80) | Closed 34-scenario hostile and recovery acceptance lane | [#99](https://github.com/vegastack/vegastack-labs/pull/99) | `454472328e22cd09e23640f27942e25a6856c2e9` |
| [4.10 (#67)](https://github.com/vegastack/vegastack-labs/issues/67) | Exact-commit integration and operator checkpoint | pending | pending |

## Requirement traceability

`tooling/phase-4-exit-evidence.json` maps the Phase 4 roadmap completion signal, all four Phase 4 Platform Core signals, all three Phase 4 Operator Experience signals, the generated contract boundary and the privacy/production boundary to the closed scenario catalog delivered by Issue #80. The catalog executes the real test selectors and rejects a missing, reordered, skipped, failed, flaky, TODO or quarantined proof.

The verifier also binds child issues to their reviewed heads and merged commits. Documentation or a child issue status is never runtime proof by itself.

## Exact-commit exit

The checked static definition names required proof but does not claim a current result. `pnpm check:phase-4-exit -- --commit <40-hex>` must start and finish at that exact clean commit, validate the complete definition and closed Phase 4 catalog, run the full public check plan plus `go test -race -count=1 ./...`, and digest the definition, scenario catalog, acceptance manifest, generated registries/client and embedded Console manifest.

A successful runtime envelope records only the exact source commit, clean-tree result, requirement and command outcomes, artifact digests, limitations and deterministic evidence digest. It is attached to Issue #67 with the matching main CI run; it is not written back into the commit whose identity it records.

After merge and exact-main proof, the operator must explicitly accept or reject Phase 4 at that 40-character commit. Until then the phase remains implemented and awaiting acceptance. Acceptance does not approve Phase 5, release, deployment, provider access, credentials or fleet operation.

## Failure and recovery

Any missing, dirty, mismatched, stale, contradictory, skipped, failed, flaky, TODO, quarantined or unsanitized proof blocks the exit. A product or security defect returns to its owning issue and the complete candidate is rerun after correction. An unavailable live system remains an explicit limitation; it is never converted into fixture success.

## Phase 5 handoff

Only after explicit Phase 4 acceptance may Phase 5 consume these declaration, authorization, acknowledgement and execution foundations. Phase 5 owns gate evidence, secret-reference resolution, backups, audit integrity, recovery epochs and restore fencing through its own approved issues and authority.
