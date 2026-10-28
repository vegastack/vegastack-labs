# Phase 10 — Operations, monitoring and agent/manual workflows

Status on 28-10-2026: source deliveries #323, #325 and #326 were merged in PR #329 after the required combined exact-head checks passed. Maintenance issue #324 and live acceptance remain open. This phase is not accepted as complete. The existing simplicity mandate, protected-host exclusion and separate source/live authority boundaries remain controlling.

## Requirements and solution

Extend the existing `vsk-labs` executable, server-owned SQLite, generated API, immutable plans and acknowledgement flow. Operators need truthful observations and alert state, bounded maintenance/repair and incident reconciliation, focused agent instructions and equivalent manual procedures. Notification destinations are delivery mechanisms; local operational truth and authorization remain in the control plane. No new queue, daemon, generic framework or privileged managed-host agent is introduced.

| Source delivery | Owner | Current acceptance boundary |
|---|---|---|
| Local operational observations, alert dedupe/recovery and optional configured Beszel/GitHub adapter source | [10.1 (#323)](https://github.com/vegastack/vegastack-labs/issues/323) | Merged with isolated alert/delivery checks and a complete plan/acknowledgement/execution/evidence workflow using real SQLite and synthetic provider/native boundaries. Final combined checks passed. No live delivery or human-read claim; a destination receipt cannot prove source recovery. |
| Hardening drift/staleness, inert maintenance/canary/drain and incident reconciliation construction | [10.2 (#324)](https://github.com/vegastack/vegastack-labs/issues/324) | Diagnosis, inert records and single-host baseline-action delegation are integrated. Plan, Slack acknowledgement and apply remain separate. Preparation alone does not prove actual maintenance execution, failed-canary stopping, drain completion or failure/recovery. |
| Nine canonical skills, generated Claude/manual copies, Hermes read/plan contract and summary diagnosis | [10.3 (#325)](https://github.com/vegastack/vegastack-labs/issues/325) | Source/contract fixtures only; native agent loading, trust and actual vendor behavior are untested. |
| Independent R2 heartbeat, external Worker checker and secondary delivery | [10.4 (#326)](https://github.com/vegastack/vegastack-labs/issues/326) | Producer, exact R2 writer, scheduled Worker/secondary source and protected server composition are implemented with local fixtures. The shared G-011 receipt verifier and protected lifecycle composition are wired and tested with synthetic boundaries. Real grants/receipts, deployment and independent detection of complete Worker nonexecution remain unqualified. |
| Optional sanitized remote status projection | Explicit selection required | Disabled; no projection is a control, approval or synchronization authority. |

The required watchdog writes sanitized status with a narrow write-only R2 identity, checks externally every five minutes and detects a heartbeat 15 minutes stale. Its local software fixtures cover dedupe, verified recovery, bounded failure behavior and concrete secondary delivery source. They do not prove live provider delivery or independent detection of a fully stopped Worker. Its live deployment still waits for G-011 recipients, a selected independent secondary route and explicit authorization. A live provider choice is not guessed to complete a fixture.

## Agent and manual source contract

The canonical source is `.agents/skills/vegastack-labs-*/SKILL.md`. Run `node tooling/agent-workflows.mjs --write` after editing it. The deterministic renderer validates each marked command template against the generated available-command registry, then writes byte-identical `.claude/skills/` and `docs/runbooks/` equivalents plus hash/provenance inventories. `node tooling/agent-workflows.mjs --check` fails on missing or changed output; the existing documentation verifier includes that drift check.

The nine workflows cover inspect, people, devices, nodes, services, network, backup/restore, maintenance and incidents. Each carries explicit input/target prerequisites, approval, verification, recovery and secret/provider/self-approval boundaries. Maintenance guidance uses the available diagnosis, inert draft and single-host repair-delegation commands; incident reconciliation remains an inert record. Unsupported aggregate execution is labelled unavailable rather than shown as working. Human/manual parity means these same prerequisites and outcomes, not an alternative provider/SQLite path.

`docs/generated/hermes-read-plan.json` is a source-derived command inventory for a future separately trusted root. It excludes apply, credential, approval, discovery and provider-refresh routes. It does not install/configure Hermes, establish trust, authenticate an OS account or enforce authorization. The server remains the enforcement boundary. Native Codex/Claude/Hermes precedence and trust must be checked on the selected pinned runtimes before claiming compatibility; synthetic instruction selection tests do not satisfy that requirement.

`vsk-labs doctor --config <protected-profile>` reuses the authenticated control summary. It diagnoses database/read/source health in a fixed order, returns the first failed invariant with the existing versioned JSON envelope and stable error codes, and shows a safe next action in human output. It performs no provider refresh, host access, direct SQLite read or mutation. Healthy summary is not host admission, a current plan or permission to apply.

## Checks and exclusions

Focused proof for 10.3 is `node --test tooling/test/agent-workflows.test.mjs`, generator `--check`, affected doctor CLI tests and changed-package vet. Root integration owns the final exact-head affected proof and the accepted source-tree mapping. Native tools, fleet/provider credentials, live monitoring, G-011 delivery evidence, release publication and deployment are outside this software check lane. No self-hosted CI dispatch is implied.

Phase 6 native, macOS/iMac and advanced-recovery deferrals remain unchanged. Neither node registration nor successful fixtures mean security qualification or workload admission. Nodes04/05 remain absolutely excluded from reads, writes, CI and indirect effects.

## Finish line and remaining evidence

Phase 10 software acceptance must map each implemented requirement to actual induced failure/recovery, alert/delivery dedupe, site-silence, source-staleness, maintenance failure/recovery, secret/provider/self-approval denial, instruction generation and manual-parity evidence. Missing capabilities remain open in the table above. Text hashes cannot replace native runtime proof, plan preparation cannot replace execution proof, and missing provider credentials cannot be called a successful live test.

Live activation additionally requires its applicable current gate evidence and separately scoped approval. Phase 9's blocked real delivery demonstration and prior live deployment gates are neither bypassed nor declared passed by this source work.
