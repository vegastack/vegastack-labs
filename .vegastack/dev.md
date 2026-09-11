# Dev profile — vegastack/vegastack-labs

This is the concise development-workflow profile consumed by the dev-family skills. The repository contract, development mandate, and approved phase material remain authoritative; this file records detected commands and workflow knobs without granting repository, release, provider, or infrastructure authority.

repo: vegastack/vegastack-labs · default branch main
stack: Go 1.27 portable CLI/control plane · Node.js 24.20.0 and pnpm 11.24.0 · Next.js 16 static Console
commands: check `npx --yes --package node@24.20.0 -- pnpm check` · affected `npx --yes --package node@24.20.0 -- pnpm check:affected -- --base <sha> --head <sha>` · build `go build ./...` and `pnpm --filter @vegastack/labs-web build` · dev `TODO — no consolidated development command exists; re-run dev-setup when one is added`
authority: `AGENTS.md` → `docs/development/operating-mandate.md` → current approved phase plan → `CONTRIBUTING.md` → this file → skill defaults

## Knobs

review: cross-agent-risky
ui-evidence: playwright
evidence-repo: vegastack/agent-dev-review-evidence
gates: 3
tests: required
skill-scan: none
merge: squash
branch: <type>/<issue>-<slug>
labels: feature bug chore needs-operator needs-plan ready working for-operator risky research quick-build full-plan epic blocked
changelog: none
decisions: docs/decisions-and-sources.md
release: on-request
chronicle: on

## Ship — permitted landing route, in order

- ask: create a pull request only after the operator explicitly requests it for the approved issue.
- guard: the exact clean branch head has one successful complete `pnpm check` immediately before the pull request is requested, invoked locally through the pinned Node wrapper shown above.
- guard: later review, rebase, or conflict-resolution edits rerun only affected checks; PR CI verifies the actual candidate through `pnpm check:affected` on the macOS 15 primary job plus the conditional Ubuntu 24.04 Linux job.
- ask: squash-merge only after a separate explicit operator instruction, required checks, and a fresh review with no unresolved correctness, security, or acceptance findings.
- auto: verify the integrated `main` commit through the affected post-merge CI plan, post the implementation/evidence summary, and close the approved issue when all acceptance criteria are satisfied.
- ask: release or deploy only under separate explicit authorization; neither is part of an ordinary merge and no release machinery currently exists.
- Rollback uses a separately approved corrective PR or targeted revert followed by the same checks and review; never rewrite shared history or treat a code rollback as infrastructure authorization.

## Verify — how to see it working before merge

- Install public dependencies: `pnpm install --frozen-lockfile` under Node.js 24.20.0 and pnpm 11.24.0.
- During implementation and review fixes, run only the narrow affected Go, tooling, web, security, failure, recovery, or integration checks.
- Run one successful complete `pnpm check` at the exact clean branch head immediately before asking for pull request creation, using the pinned Node wrapper shown above.
- PR and `main` CI run `pnpm check:affected` from explicit base/head commits on the GitHub-hosted macOS 15 primary job. A small GitHub-hosted Ubuntu 24.04 Linux compatibility job runs `go test ./...` only when that plan identifies Go/Linux impact; neither job uses fleet machines. Browser installation and Playwright run only for browser-impacting changes. A missing, invalid, or unclassifiable diff fails closed to the full suite and Linux lane.
- Explicit phase-acceptance commands remain required by their owning issues and are never replaced by the generic selector.
- UI evidence uses the pinned Playwright lane and the private evidence repository named above.
- Verification uses isolated local/CI fixtures. It never treats fixture results as live provider, hardware, or deployment-gate evidence.

## Environments

- Local development: this checkout or an issue-scoped worktree; public dependencies and synthetic fixtures only.
- Public CI: a GitHub-hosted macOS 15 primary job with pinned Go, Node.js, pnpm, and immutable action commits, plus a small conditional GitHub-hosted Ubuntu 24.04 Linux compatibility job for `go test ./...`.
- Production-like and inventory-fleet targets: unavailable to ordinary development; require their own closed gates and explicit authorization.
- Optional maintainer registry variable names are documented in `web/.env.example`; values never enter Git, prompts, plans, issues, or audit records.
- Local toolchain gap: the system default is not the pinned Node.js version; use the recorded `npx --yes --package node@24.20.0 -- ...` form for the complete lane.

## Design

- The Console uses `@vegastack/design`, `@vegastack/design-tokens`, and the registry/component contract in `web/components.json`.
- Preserve the statically exported Next.js Console and generated API-client boundary; UI code must not create an alternate authorization, provider, or SQLite path.

## Architecture

hosting: self-managed `vsk-labs server run` with an embedded statically exported Console; current repository is pre-launch
database: local server-owned SQLite is authoritative operational state
auth: provider-neutral platform grants and human-acknowledgement policy with typed identity adapters
storage: optional off-site object backup is disaster recovery only, never runtime authority
jobs: no separate queue or worker service is currently implemented
agents: typed optional integrations; no custom privileged agent on managed hosts
stage: pre-launch
kind: oss
mobile: no

## Decisions

Record a decision only when it steers work beyond one issue, rejects a real alternative, and cannot be enforced by an existing rule or deterministic guard. Every entry needs the user's explicit confirmation and must follow the existing D-numbered format and evidence conventions in `docs/decisions-and-sources.md`; do not append an unstructured parallel ledger.

## Stop and ask

Dark execution ends and the operator decides when work would change scope or product behavior, add a significant dependency or runtime, spend money, perform a destructive action, touch production or the inventory fleet, change repository policy/settings, publish a release, or encounter a blocker the approved issue cannot resolve. Nothing ships without the operator's explicit instruction.

## Project rules

- Work only in an explicitly approved named issue/batch; later roadmap issues are not implicitly ready.
- Preserve the portable-platform, typed-adapter, optional-capability, and Labs deployment-profile boundaries.
- Use the workflow state and scope labels recorded above as directed by the active VegaStack skill.
- Human-readable project dates use `DD-MM-YYYY`; times use the 12-hour clock with explicit AM/PM in IST.
- Never expose plaintext secrets or private operational state.
