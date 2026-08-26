# Product-and-engineering issue template

Status: working v1, adopted with the [operating mandate](operating-mandate.md) on 26-08-2026.

This is a drafting format, not an instruction to publish an issue or mark it Ready. Replace placeholders with real, approved information. Keep every applicable concern; reference unchanged shared contracts instead of repeating them. Do not pad small issues with irrelevant sections.

Use `DD-MM-YYYY` dates and 12-hour IST times with explicit AM/PM in issue text, approval records, and comments; follow the [repository date/time convention](../../AGENTS.md#dates-and-times). Machine evidence retains its required timestamp format.

The published issue is a living implementation plan. Keep its body current; no manual revision number or body hash is required. Explain meaningful changes in comments, but never leave executable instructions only in discussion. Routine implementation detail updates stay autonomous; mark material scope/behavior/security/acceptance changes pending until the user confirms them.

Use `<phase>.<issue>` IDs: `0.1` is the first issue of development phase `0`; `1.1` is the first issue of development phase `1`. Issue numbers continue across batches within a phase. Use the ID in the title and references; GitHub's `#number` remains a separate link. Sort IDs by their two integer components, not as decimals. See the [numbering and filename conventions](README.md#planning-structure).

## Executable issue body

```markdown
# [<phase>.<issue>] <observable outcome>

Development issue: <phase>.<issue>
Development phase: <phase number and milestone>
Approved batch: <batch identifier; does not change the issue number>
Type: <feature | bug | chore>
Approval record: <phase/batch record with actual user confirmation and constraints>
Depends on: <development IDs plus GitHub links, e.g. 0.2 (#17); or explicitly none>
Required reading: <repository instructions, mandate, relevant spec/phase sections and baseline references>
Execution defaults: <shared phase/repository setup and checks; specify differences below>
Finish line: <merged and closed; any explicitly approved exception>

## Outcome and boundaries

Who needs this, what problem exists, and what will become possible or correct?
Describe scope, explicit exclusions, and the before/after operator or system behavior.
Identify the owning layer (core/adapter/optional capability/profile), generic behavior,
selected dogfood values and unsupported combinations. Never turn a Labs value into
a core prerequisite. Include account-free/basic and non-Labs fixture acceptance where applicable.

## Behavior and interfaces

Specify the relevant user journeys and API/CLI/UI behavior, inputs/outputs,
validation, errors, and positive/negative/empty/stale/interrupted cases.
Pin affected shared contracts; identify compatibility obligations, disabled/unconfigured
capabilities, profile/policy provenance and the public credential-free build path where relevant.

## Implementation and data

State the agreed approach, affected components/interfaces, dependencies,
data ownership/schema changes, and migration/upgrade implications.
Give ordered steps and exact target files/algorithms where needed; keep them current.
Name what local implementation choices remain delegated to the agent.
Include rollback/recovery when applicable; do not invent a safe rollback.

## Security, failure, and operational behavior

Address the relevant identity/authorization/trust boundaries, secret handling,
denied actions, audit/redaction, retries/timeouts, idempotency/concurrency,
partial failures, recovery, resource limits, and diagnostics.
Reference inherited controls and identify any changed boundary explicitly.

## Acceptance and verification

| ID | Scenario / expected outcome | Check, fixture/environment, and required evidence |
|---|---|---|
| AC-01 | <observable behavior, including exact failure behavior where relevant> | <command/procedure, expected result, artifact> |

List the baseline and changed-behavior checks in execution order.
Specify tool/runtime versions, fixture setup/cleanup, and any integration,
security/denial, recovery, performance, accessibility, or visual checks needed.
If this issue creates its harness, define the resulting commands and assertions.
Distinguish fixture proof from authorized live evidence. No required check is
silently skipped or replaced. Include the fresh adversarial review focus.

## Execution conditions and stop rules

Allowed repository/environment/targets: <explicit scope>
Required access and inputs: <available inputs and logical references; no secrets>
Merge prerequisites: <required checks, review route, supported identities;
no unapproved automation side effects>
Parallelism: <approved independent issues; otherwise dependency-ordered>
Stop for: <specific material ambiguities, unsafe conditions, or missing inputs>
Known limitations / later gates: <explicit consequence; not a claim of success>

## Delivery and effort

Deliver: <code/configuration, meaningful tests, docs/runbook/generated changes,
PR(s), fresh review disposition, and GitHub implementation-summary comment>
Agent estimate: <minutes; basis in files/turns and command runtimes, including review>
2× checkpoint: <minutes; stop and check in>
User review: <expected minutes for this planning/approval step>
External waits: <CI/provider/hardware/user waits separately, or none>
```

The acceptance table is the proof map. Do not create a duplicate test matrix unless needed. Criteria must be falsifiable; “works,” “secure,” and “production ready” are inadequate. If this issue owns phase acceptance, include the combined exit demonstration, its contributing dependencies, and evidence for each phase exit criterion. A separate acceptance issue is optional, not a requirement for every phase.

## Claim comment

The coordinator verifies the current issue and approval reference, checks readiness and existing claims, and confirms the assignment. A lone executing agent may also coordinate. Record the responsible human, agent/session, plan/approval reference, base commit, branch/worktree, readiness result, and start time. Keep paths and session metadata publication-safe. For a handoff, record verified work, outstanding changes/checks, and next action; confirm the old worker has stopped before reassigning.

## Implementation summary comment

```markdown
## Implementation summary — <phase>.<issue>

## Delivered
<What the operator/system can now do; relate it to the issue outcome.>

## Changes and rationale
<Substantive changes, affected components, and why this approach satisfies the contract.>

## Security and failure behavior
<Relevant safeguards, denials, compatibility/recovery behavior, and limitations.>

## Verification
<AC IDs → commands/procedures, environment/versions, commit, result, and artifact links.>
<Fresh adversarial review: reviewed commit, findings, fixes, and final disposition.>
<Explicitly distinguish fixture coverage, live proof, and any separately gated work.>

## Delivery references and effort
<PRs, integrated commit, and documentation/runbook links.>
<Estimated versus actual agent minutes; external waits separately.>
<Required follow-ups or limitations, without hiding unmet acceptance criteria.>
```

Use concise connected prose and small lists/tables where they help. Summarize all substantive changes; do not copy the full diff or raw logs. Unmet acceptance keeps the issue open. Fixable failures stay in the agent's rework loop; use `blocked` only when progress needs a decision/input/authority/environment outside the approved contract. Do not hide unmet acceptance as follow-up notes under a success heading.

## Blocker or checkpoint comment

Record what is complete and verified, the exact blocker or timebox overrun, supporting sanitized evidence, what did not change, dependent work affected, and the smallest decision/input or revised plan needed. Preserve branch/commit references for resumption. Ask through the available clarification tool with a recommended option for a design decision; follow the separate runtime authorization process where permission is required.
