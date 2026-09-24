# Phase 5 hostile and recovery acceptance

`pnpm check:phase-5` is the credential-free adversarial acceptance command for Development Phase 5. It validates one closed, code-owned catalog and executes its exact Go, Node, and Playwright selectors against the merged gate, credential, backup, audit, restore, scheduler, API, CLI, and Console seams.

The catalog lives at `tooling/testdata/phase-5/acceptance-scenarios.json`. Every row binds a requirement, owning issue, seam, test kind and path, exact selector, environment, expected result, repeat and seed policy, cleanup owner, and sanitizer. `tooling/phase-5-evidence.json` lists the same scenario IDs in the same order and has no quarantine channel. The verifier rejects a missing, added, renamed, reordered, weakened, skipped, TODO, quarantined, flaky, multiply matched, or falsely live proof before treating the lane as valid.

## Running the lane

Run from a clean committed checkout with the pinned project toolchain:

```bash
npx --yes --package node@24.20.0 -- pnpm check:phase-5
```

The command builds the Console unless `--prepared` is supplied by the complete check, checks generated contracts and public CLI/static boundaries, then runs every catalog selector. Go selectors use the race detector and `-count=1`. Seeded concurrency rows use `VSK_PHASE5_SEED=phase5-concurrency-v1` and every declared repetition must pass; a failure is never retried into success. Browser work uses one worker and a temporary artifact root. Temporary runtimes and artifacts are removed in `finally` paths after success or failure.

A successful run writes one canonical JSON line:

```json
{"schemaVersion":1,"check":"phase-5","status":"pass","executionEnvironment":"portable|linux","sourceCommit":"<40 lowercase hex>","scenarioDigest":"sha256:<64 lowercase hex>","scenarioOutcomes":{"<scenario-id>":{"environment":"fixture|chromium|built-linux","status":"pass|linux-required"}}}
```

The source commit and canonical definition digest make repeated results at the same clean commit comparable byte for byte. A portable host reports Linux-only rows as `linux-required`; it never records those rows as passes. Issue #112 owns the single full Linux/browser exact-main Phase 5 exit run and must turn every required row into executed proof before final acceptance.

## Safety and failure ownership

All rows use `proofClass=fixture`. They use temporary SQLite databases, temporary filesystem roots, fixture credentials, and synthetic provider endpoints. They do not satisfy live `G-007`, `G-008`, site recovery, provider, storage, host, release, deployment, or fleet evidence.

Captured child output is bounded and scanned for the public Phase 5 private canaries. Success emits no child diagnostics. Failure emits only a code-owned stage and, when available, a closed catalog scenario ID. Raw child output, paths, tokens, cookies, secret material, private payloads, provider errors, and assertion text are discarded.

A deterministic product failure belongs to the issue named by the catalog row. Reopen or correct that owning issue. Do not weaken, skip, reorder, quarantine, relabel, or retry the scenario in this lane. Issue #111 owns the catalog and runner; issue #112 owns final exact-main integration evidence.
