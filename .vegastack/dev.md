# Dev profile — vegastack/vegastack-labs

This is the concise development-workflow profile consumed by the dev-family skills. The repository contract, development mandate, and approved phase material remain authoritative; this file records detected commands and workflow knobs without granting repository, release, provider, or infrastructure authority.

repo: vegastack/vegastack-labs · default branch main
stack: Go 1.27 portable CLI/control plane · Node.js 24.20.0 and pnpm 11.24.0 · Next.js 16 static Console
commands: check `npx --yes --package node@24.20.0 -- pnpm check` · affected `npx --yes --package node@24.20.0 -- pnpm check:affected --base <sha> --head <sha>` · build `go build ./...` and `pnpm --filter @vegastack/labs-web build` · dev `TODO — no consolidated development command exists; re-run dev-setup when one is added`
authority: `AGENTS.md` → `docs/development/operating-mandate.md` → current approved phase plan → `CONTRIBUTING.md` → this file → skill defaults

## Knobs

review: subagent            # operator instruction 18-09-2026: independent Codex reviewers; no Claude before 22-09-2026 04:30 AM IST. Revisit after cutoff; setting does not auto-revert.
ship-check: local-affected-exact-head # intermediate Phase 5 issues run the configured affected command locally once against exact current-main base and clean local/remote/evidence HEAD; final Phase 5 integration/acceptance alone uses manual Public CI with explicit full_check. The installed guard is workstation-local and a fresh machine needs the matching skill update.
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
- guard: before asking for an intermediate Phase 5 pull request, the installed dev-ship guard runs the configured local affected command once with the exact current remote `main` SHA and clean local/remote/evidence branch HEAD, then rechecks every binding. The final Phase 5 integration/acceptance candidate alone explicitly selects manual Public CI `full_check`. Missing, dirty, stale, or unverifiable state blocks.
- guard: later review, rebase, or conflict-resolution edits rerun only the local affected checks. During the Phase 5 batch, pull requests and `main` pushes do not trigger Public CI; explicit final-full and named native acceptance dispatches may use the two authorized disposable Debian hosts.
- ask: squash-merge only after a separate explicit operator instruction, required checks, and a fresh review with no unresolved correctness, security, or acceptance findings.
- auto: verify that the integrated `main` tree matches the reviewed branch tree, post the implementation/evidence summary, and close the approved issue when all acceptance criteria are satisfied; do not start post-merge CI during the Phase 5 batch.
- ask: release or deploy only under separate explicit authorization; neither is part of an ordinary merge and no release machinery currently exists.
- Rollback uses a separately approved corrective PR or targeted revert followed by the same checks and review; never rewrite shared history or treat a code rollback as infrastructure authorization.

## Verify — how to see it working before merge

- Install public dependencies: `pnpm install --frozen-lockfile` under Node.js 24.20.0 and pnpm 11.24.0.
- During implementation and review fixes, run only the narrow affected Go, tooling, web, security, failure, recovery, or integration checks.
- For intermediate Phase 5 issues, run the pinned local `pnpm check:affected` command once against the exact current remote `main` commit and exact clean, pushed branch head immediately before pull request creation. Changed Go files test and vet only their package directories while repository-wide compilation and selected boundary verifiers remain. The final Phase 5 integration/acceptance candidate alone selects manual Public CI `full_check` once.
- Public CI has only a manual `workflow_dispatch` trigger during the Phase 5 batch. It accepts the explicitly selected final-full lane and named native acceptance inputs; pull requests and `main` pushes start no workflow. Under the temporary Issue #81 exception, those explicit dispatches may use disposable `vsk-node-01` or `vsk-node-06`; the job checks the hostname before checkout and has no fleet-admin or deployment credentials.
- The `web/` Playwright e2e suite shares a module-global fixture (`fixtureState`) and MUST run single-worker: `pnpm exec playwright test … --workers=1` (or set `VSK_PHASE3_PLAYWRIGHT_OUTPUT`, which pins one worker). Parallel runs race and report spurious, shifting failures. Rebuild the static export before every e2e/screenshot run — `next build` type-checks the `e2e/` specs and, when it fails, leaves a **stale `out/`** that `pnpm preview` keeps serving, so trust only a fresh clean build. Read counts from the `list` reporter, never the `line` reporter (its overwriting summary hides failures). If Playwright reports every test failing at ~0ms, the browser binary is missing — `pnpm exec playwright install chromium chromium-headless-shell`.
- Explicit phase-acceptance commands remain required by their owning issues and are never replaced by the generic selector.
- UI evidence uses the pinned Playwright lane and the private evidence repository named above.
- Verification uses isolated local/CI fixtures. It never treats fixture results as live provider, hardware, or deployment-gate evidence.

## Environments

- Local development: this checkout or an issue-scoped worktree; public dependencies and synthetic fixtures only.
- Public CI: manual dispatch only during the Phase 5 batch. Explicit final-full and named native acceptance runs may temporarily use disposable Debian `vsk-node-01` or `vsk-node-06` under Issue #81; this is not permanent runner admission or fleet qualification.
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
