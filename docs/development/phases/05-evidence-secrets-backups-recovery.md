# Development phase 5 — Evidence, secrets, backups, and recovery

Status: implemented and awaiting operator acceptance. The candidate combines the closed software deliveries through Issue 5.10 and binds them to one exact-commit Debian exit. It does not claim live infrastructure evidence, activate G-007 or G-008, publish a release, or authorize deployment.

## Delivered behavior

Phase 5 added provider-neutral evidence and gate evaluation, consumer-bound credential lifecycle and recovery, verified local and off-site recovery points with separate retirement rules, tamper-evident audit history, fenced single-authority restore, exact scheduled operational policies, and shared CLI/API/Console surfaces. Issue 5.10 owns the closed 47-scenario hostile and recovery catalog used by the exit verifier.

The machine-readable ownership record is [`tooling/phase-5-exit-evidence.json`](../../../tooling/phase-5-exit-evidence.json). It binds every implementation owner to its final reviewed branch head and squash merge, records the three research/qualification outcomes without inventing implementation PRs, and maps credential umbrella Issue #105 to its exact child set. Later children merged while Public CI was manual-only; their absent per-child run is represented by the single epic exit rather than a fabricated URL.

## Issue and integrated-commit index

| Scope | Issues | Integrated proof |
|---|---|---|
| Contracts, qualification, gates | #102–#104 | Final evidence/review records and retained squash merges; #103 is research-only. |
| Credentials | #105, #123–#125, #132–#135, #139–#146, #153, #159 | #105 is map-only; #139/#145 are qualification records; implementation children bind exact reviewed heads and merges. |
| Backups and retention | #106, #114, #115, #117, #118, #154 | Local/off-site creation, verification, custody, dependency admission, and exact retirement remain separate authorities. |
| Audit, recovery, schedules, surfaces | #107–#110 | Audit checkpoints, authority fencing, exact schedule occurrences, and generated operator surfaces compose through the shared engine. |
| Hostile acceptance | #111 | 47 ordered credential-free scenarios, including built-process crash seams and real SQLite concurrency authorities. |
| Exact phase exit | #112 | One clean Linux `origin/main` commit, one full public plan, one focused race pass, immutable artifact digests, and explicit operator acceptance after proof. |

## Traceability and proof boundary

Every roadmap requirement in the evidence definition owns one or more exact #111 proof IDs, and every one of the 47 IDs is owned. The verifier rejects reordered, missing, unknown, unfinished, skipped, flaky, quarantined, falsely live, or unsanitized proof. It also rejects a dirty checkout, a non-Linux runner, a stale `origin/main`, missing child merge ancestry, changed accepted Phase 3/4 ancestry, or artifact drift.

All catalog outcomes have `proofClass: fixture`. Built Linux processes, SQLite databases, pinned public binaries, and Chromium still run in isolated development fixtures. They are software-development evidence, not provider, vault, host, site, or fleet evidence.

## Failure and recovery

A product or security failure reopens its owning implementation issue. A Phase 5 evidence-definition, documentation, or verifier defect is corrected in #112 and rechecked. A dirty or moved commit is never accepted; create a new exact candidate. Failed exact-main evidence blocks acceptance without retry-based promotion.

The recovery model stays fail-closed: incomplete local/off-site points remain unusable, retirement preserves required survivors, returning old writers and plans stay fenced, and a failed promotion canary remains recovery-required. The exit verifier observes these behaviors but cannot perform a live restore.

## Explicit limitations

- G-007 physical vault partitions, live secret-provider custody, provider grants, and direct-provider denial are not exercised.
- G-008 live storage, host, site, and control-authority recovery are not exercised.
- No release, deployment, provider/credential access, host change, network change, milestone closure, or fleet operation follows from this candidate.
- Acceptance occurs only after exact-main proof and the operator's explicit accept/reject words are recorded. A merge, green run, or silence is insufficient.

## Phase 6 handoff

Phase 6 may consume the accepted software contracts for isolated host-lifecycle work only after Phase 5 is explicitly accepted. It must supply its own supported-OS, hardening, reboot, idempotence, lockout-recovery, and admission proof. Phase 5 fixture results cannot substitute for those real-host requirements.
