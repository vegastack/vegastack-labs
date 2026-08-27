# Development operating mandate

Status: adopted as working v1 by the user on 26-08-2026. Phase plans, issue batches, and operational authority still require their applicable approvals.

## Workflow at a glance

1. Agree the phase outcome, scope, solution, and final demonstration with the user.
2. Develop and approve the next issue batch together, settling consequential decisions.
3. Check readiness, assign one owner per issue, and execute in dependency order.
4. Keep the issue's plan current. Build, test, obtain fresh adversarial review, and fix findings.
5. Merge through the permitted route, verify the integrated result, post the implementation summary, and close.
6. Prove the phase outcome through its designated acceptance issue, then plan the next batch or phase.

Routine choices and fixable test/review failures stay with the agent. Ask the user for a material change, an obstacle that cannot be resolved within the approved scope, or the 2× checkpoint.

## 1. Purpose and authority

Build VegaStack Labs through small, ordered issues that agents can execute without routine human involvement. The user shapes requirements and solutions at phase and issue-batch level. Autonomous execution starts after batch approval.

The aim is no unresolved consequential decisions about behavior, interfaces, security, data, or acceptance. Agents retain judgment over ordinary implementation details.

This mandate governs development, not fleet authority. [AGENTS.md](../../AGENTS.md), the canonical specifications, and operational gates remain binding. A merged PR, closed issue, milestone, or agent review is never infrastructure authorization or live activation evidence. No agent bypasses repository protection, impersonates an approver, or weakens checks.

Ordinary development uses repository tools and isolated tests, without depending on the not-yet-built `vsk-labs` runtime. The current root contract still needs an approved clarification before general autonomous GitHub work starts; see [one-time setup](README.md#before-autonomous-execution). This mandate does not itself grant that authority. Fleet operations, repository administration, releases, and production-like tests retain their separate authorization requirements.

## 2. One home for each kind of information

| Information | Canonical home |
|---|---|
| Platform behavior, architecture, and safety | Existing focused specifications and decision register |
| Development rules and reusable issue format | This mandate and the [issue template](issue-template.md) |
| Complete v1 scope allocation and phase dependencies | Development roadmap |
| Phase requirements, solution, batch approvals, shared setup, and exit criteria | One document per development phase |
| Current execution plan, work state, discussion, and delivery evidence | GitHub issue and linked PR(s) |
| Private operational intent, approvals, and evidence | Existing control-plane storage; never GitHub or public planning docs |

Link instead of duplicating. Give each issue a small required reading set, including repository instructions and relevant specification/phase sections. Use commit references where needed to identify the reviewed baseline; check relevant changes at claim and merge. An old reference never overrides current safety instructions.

When a plan or contract changes, proactively update every affected open issue before following the changed plan. Update the owning specification/phase document as applicable. Comments explain decisions; the issue body contains the current executable instructions. Stop affected work on a contract conflict. Regenerate generated artifacts through their owner, never by hand.

## 3. Plan phases; maintain living issues

Use development phases `0`, `1`, `2` and issues `0.1`, `0.2`, `1.1`, following the [numbering and filename conventions](README.md#planning-structure). IDs stay stable across batches and plan changes; explicit dependencies determine execution order. Development phases prove implemented capabilities; the existing deployment phases require actual site evidence.

For each phase:

1. Brainstorm requirements, scope/exclusions, solution, security boundaries, dependencies, and an integrated exit demonstration with the user.
2. Settle phase-level decisions and map the work into small issues. Later issues may remain drafts; consequential questions affecting the next batch must be resolved before its approval.
3. Brainstorm and approve the next batch's issue requirements and approach with the user. Identify the issues and agreed boundaries, not just the phase name.
4. Execute the approved batch. Return for the next planning checkpoint, a material blocker, or the 2× timebox.
5. Demonstrate the combined phase outcome before closing its milestone.

Keep one short batch approval record in the phase document: approver, date, phase/batch, issue links, coordinator, and constraints. Record actual user confirmation; agents cannot supply it. One approval can cover an enumerated batch. No mandatory body hashes, manual revision counters, or repeated approval of unchanged requirements.

### Keep the issue current

Issues may be edited as often as needed. During planning, refine them freely. During execution, agents may update steps, file locations, internal structure, and test implementation while preserving the agreed outcome, interfaces, safety, scope, and required proof. Update the body before using the changed plan. Comment on meaningful changes and why they were made; formatting and typos need no ceremony. Routine plan edits do not remove `ready` or require user approval.

A material change to scope, observable behavior, shared interfaces, security/authority, data compatibility, recovery commitments, or acceptance requires user confirmation. Mark proposed changes as pending, remove `ready`, and stop affected execution; editing a description is not approval. Once confirmed, update the body, relevant canonical documents, and dependent issues, then recheck execution conditions. Never leave the operative decision only in a comment or chat.

Closed issues preserve delivery history. New requirements get follow-up work; unmet original acceptance reopens the original issue.

Map all in-scope v1 requirements to phases early. Detail the next batch against actual code and interfaces rather than freezing speculative implementation steps for distant phases.

## 4. Design complete, executable issues

Each issue states what to build, why, the chosen approach, explicit exclusions, and independently verifiable outcomes. Settle observable behavior and cross-component decisions. Prescribe exact files, algorithms, sequences, migrations, or recovery steps where correctness requires them; delegate ordinary coding choices. Do not invent existing files, tools, inputs, or test commands.

Prefer one coherent outcome and normally one PR. Keep related API/CLI/UI/data work together when reviewable; split larger work on settled interfaces and assign combined acceptance. Split unresolved research into an approved, timeboxed investigation with a decision/evidence deliverable. Dependent implementation waits for that decision. Multiple PRs are acceptable when planned, but all delivery obligations must finish before closure.

Cover applicable product/UX, interfaces, data, security, failure, compatibility, performance, operations, tests, and docs. Reference unchanged shared controls. Avoid irrelevant essays, arbitrary coverage percentages, and splitting solely by technical layer or file count.

Put shared toolchain, fixture setup, check commands, and merge requirements in phase execution defaults or an existing repository guide. Issues link to those defaults and state their differences. Check changes to shared defaults against affected open issues.

### Ready checklist

The coordinator reads the issue as a new executing agent: is it clear what to build, what must stay unchanged, and how to prove completion without making a consequential decision?

Apply `ready` only when:

- the user has approved the issue in its batch, with scope, acceptance, authority, and stop conditions settled;
- required dependencies are merged, their required verification is complete, and their contracts still match;
- inputs, fixtures, tool versions, environment, and repository access are available;
- checks have concrete commands/procedures and expected results, directly or through linked defaults;
- the permitted merge route, review identities, and required checks are satisfiable without bypass or unapproved deployment, release, policy, or privileged side effects;
- the agent estimate, basis, 2× checkpoint, and external waits are recorded.

A fresh review agent is not automatically a separate GitHub approver. If required human approval is unavailable, do not promise autonomous delivery. A bootstrap issue may create its own harness, but must define the resulting checks and clean-checkout procedure and have an independently permitted delivery path.

Recheck readiness at claim. Changed material contracts or failed prerequisites affect only relevant issues. Fixture-based work need not wait for unrelated live gates, but cannot claim live proof. See the [setup checklist](README.md#before-autonomous-execution); a documented command is not an implemented check.

## 5. Execute, recover, and resume

One named coordinator owns batch assignments and merge order. With one executing agent, that agent may also coordinate; no extra manager is required. For parallel work, only the coordinator confirms assignments. Workers do not race to claim an issue.

The claim comment records the responsible human, agent/session, current plan/approval reference, base commit, branch, readiness result, and start time. Remove `ready` when claimed. Use an isolated worktree and the repository's type-based branch convention: `feat/<issue-id>-<short-slug>` for `feature`, `fix/<issue-id>-<short-slug>` for `bug`, or `chore/<issue-id>-<short-slug>` for `chore`. Never use agent-name prefixes such as `codex/` or `claude/`. Preserve unrelated changes, inspect affected code, and run relevant baseline checks before editing. Distinguish existing failures from regressions.

Execute in dependency order. Parallel issues must be explicitly identified as independent in the approved batch, with isolated worktrees and settled shared interfaces. Avoid competing ownership of migrations/generated sources. Serialize merges and verify the integrated result. An unmerged dependency branch is not a completed prerequisite unless that workflow was specifically approved.

Agents fix defects needed to meet the contract and keep their implementation plan current. They may not expand scope, deviate from agreed behavior, relax security, invent inputs, weaken acceptance, or silently add a material dependency. Unrelated discoveries become proposed follow-ups.

### Rework is not a blocker

Failing tests and fixable review findings stay in the normal investigate/fix/test/review loop within the contract and timebox. Use `blocked` when progress needs a decision, input, authority, or environment the agent cannot safely obtain within that contract.

Remove `ready` when marking work `blocked`. Preserve work and comment with evidence, completed work, the exact obstacle, affected dependencies, and the smallest safe next step. Independent approved work may continue. After resolution, update the issue if needed, clear `blocked`, and recheck conditions before resuming or returning unclaimed work to `ready`.

For design choices, use the available clarification tool with a recommended option when applicable. Missing confirmation cannot authorize a material change. Permission and infrastructure-authorization requests follow their separate procedures.

For interrupted work, leave a short handoff: branch/commit or preserved worktree, verified work, outstanding changes/checks, and next action. If interruption prevented a comment, the successor inspects and records recovered state before editing. The coordinator confirms the previous worker has stopped before reassignment; elapsed time alone is not permission to take over. Recheck the current issue and preserve unrelated/uncommitted work.

## 6. Review and verify

Each implementation issue receives a fresh review agent, separate from the implementer. Supply the current issue and approved boundaries, required reading, diff/commit, relevant surrounding code, and test evidence. The reviewer must inspect the work, not just the completion narrative.

Review proportionately for contract mismatches, unsafe assumptions, secret/authorization failures, state transitions, concurrency/idempotence, compatibility, failure/recovery, and tests that can pass despite broken behavior. UI work also needs applicable workflow, accessibility, and visual checks. Documentation changes need correctness/consistency checks, not irrelevant runtime tests.

Run existing narrow unit/schema/fixture checks first, then relevant integration, plan/idempotence, failure/recovery, and supported-platform checks. Add tests for meaningful gaps and reuse fixtures. Check relevant denials as well as success. Fixtures are not live provider or hardware evidence.

Record actionable findings, their disposition, and the reviewed commit in the PR. Fix findings and rerun affected checks. Later changes, including conflict resolution, require relevant renewed checks and review; old review cannot certify unseen changes. No ritual review rounds or unrelated perfectionism.

Unresolved correctness, security, or acceptance findings prevent merge. They require user input only when resolution exceeds the approved contract or available prerequisites. Agents cannot accept a new material risk for the user.

Evidence identifies the commit, environment/versions, exact commands/procedures, results, and relevant artifacts. Failed, skipped, unavailable, or flaky required checks are not passes. If required proof cannot be obtained, block affected work or obtain an approved scope change; never substitute an illustrative result.

## 7. Merge, close, and accept the phase

The normal finish line is merged and closed. Before closure:

- all acceptance criteria have evidence appropriate to their stated environment;
- fresh review has no unresolved correctness/security/acceptance findings;
- required checks pass for the actual merge candidate/integrated commit, including required post-merge checks;
- relevant specifications, generated output, migrations, runbooks, and user docs are updated;
- all delivery PRs are merged through the permitted route;
- the issue has its implementation/evidence comment and PR/commit links.

Merging alone does not complete pending verification. If post-merge checks fail, keep/reopen the issue and follow the approved recovery procedure. No silent force-push, history rewrite, or unapproved revert. Development completion may leave separate live activation gates open; state that distinction explicitly.

Each phase names an issue responsible for its combined acceptance demonstration. It may be the final delivery issue; create a separate integration issue when the combined checks warrant their own scope. The owner depends on the contributing deliveries and proves the operator outcome, relevant failures/recovery, and every phase exit criterion. Its completion comment links evidence, limitations, and next planning inputs.

Close the milestone only when the exit criteria and all required phase issues are satisfied. Later-phase work still needs approval.

## 8. Minimal GitHub conventions

Use one milestone per development phase: `Phase <phase> — <name>`. Use only these five labels for this workflow:

| Label | Meaning |
|---|---|
| `feature` | Adds or intentionally changes product/platform capability |
| `bug` | Corrects a violation of an accepted contract |
| `chore` | Tooling, refactoring, documentation, or investigation |
| `ready` | Approved, unclaimed work with verified prerequisites |
| `blocked` | Cannot proceed within the approved contract |

Use exactly one type label. `ready` and `blocked` are mutually exclusive; unapproved drafts have neither. Assignment/claim and PR status show active/review work; closure with evidence shows completion. Clear transient readiness/blocker labels when closing. No project board or extra status labels. Add a label only for an agreed, repeated retrieval/automation need.

The type label also selects the branch prefix: `feature` uses `feat/`, `bug` uses `fix/`, and `chore` uses `chore/`. Continue the name with the development issue ID and a short kebab-case outcome, for example `feat/2.1-inventory-read-api`. The canonical rule and authority boundary are in [AGENTS.md](../../AGENTS.md#development-branch-names).

Titles start with the development ID and outcome: `[2.1] Reject expired plans before secret resolution`. GitHub's automatic number is separate: `2.1 (#23)`. Carry the development ID into PR references and implementation summaries. Numbers and availability never bypass dependencies.

Post substantive implementation summaries in GitHub issue comments using the [template](issue-template.md#implementation-summary-comment): observable result, important changes/reasons, security/failure behavior, acceptance-to-evidence mapping, limitations, PR/commits, and actual effort versus estimate. Link detailed PR review and test artifacts rather than copying logs. A bare “done” is insufficient.

Keep routine progress concise and non-blocking. Record claims, meaningful plan changes, blockers/handoffs, and completion; do not mirror every tool call.

## 9. Effort and maintenance

Use the repository's [date and time convention](../../AGENTS.md#dates-and-times): human-readable dates are `DD-MM-YYYY`, and times use the 12-hour clock with explicit AM/PM in IST. Preserve required machine timestamp formats.

Follow the repository's agent-executed estimate convention: expected agent minutes, basis in files/turns and command runtimes, a 2× checkpoint, user review time, and external waits. Include review/rework and verification. Log phase/batch starts and ends, compare actuals, and update rates on drift. Separate parallel clocks and user/CI/provider waits from active agent effort; do not estimate human engineering days.

At 2×, preserve state and report completed/remaining work and the overrun reason. Do not silently extend the budget or call incomplete work done.

Keep the workflow stable and the plans current. Improve rules/templates when experience reveals a repeated ambiguity or missing proof. No new planning service, custom issue database, approval mechanism, or orchestration framework is needed. Markdown, GitHub, repeatable checks, and proportionate agent review are sufficient.
