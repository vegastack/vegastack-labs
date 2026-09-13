# Phase 4 acceptance

`pnpm check:phase-4` is the credential-free acceptance command for declarations, immutable plans, authorization, Slack acknowledgement, durable runs, external executor leases, browser recovery, and private-data exclusion.

The command uses only generated contracts and isolated fixtures. It does not contact Slack, a provider, a managed host, or the inventory fleet, and it grants no release or deployment authority.

## What the command proves

The verifier owns an independent, hard-coded closed scenario ID list, then requires both `tooling/testdata/phase-4/acceptance-scenarios.json` and `tooling/phase-4-evidence.json` to match it exactly. Editing both JSON files therefore cannot silently remove a proof. Each entry must point to an actual Go, Node, or Playwright test file; helper scripts and ordinary source files are not accepted as proof.

On every supported development host it:

1. captures a clean tracked/index Git commit, verifies the generated contracts, built CLI boundary, static Console, and closed acceptance definition;
2. builds the Console unless the parent check already built it;
3. drives the generated browser client through exact plan display and checks that protected acknowledgement, executor, provider, and SQLite paths never enter the browser; and
4. parses machine-readable test output and requires one exact passing result for every portable scenario (zero matches, failures, skips, TODOs, unsupported tests, or extra Playwright matches fail); and
5. scans retained browser output with the existing bounded artifact sanitizer, then proves the same clean commit is still checked out with no tracked/index drift.

On Linux it additionally:

1. runs the Phase 4 adapter, acknowledgement, API, authorization, CLI, plan, run, and SQLite packages with the race detector;
2. builds the real `vsk-labs` executable with the temporary database and Debian release fixture bound at link time;
3. launches `vsk-labs server run` against an authoritative temporary SQLite database and real loopback TLS; and
4. exercises the server-owned Slack fixture, local typed adapter, interruption, resume, cancellation, external executor, receipt, and recovery paths.

The production adapter registry stays empty. Test adapters and synthetic identities exist only in test files and cannot be selected by a normal build.

## Deterministic result

A successful run writes one JSON line to stdout:

```json
{"schemaVersion":1,"check":"phase-4","status":"pass","executionEnvironment":"portable|linux","sourceCommit":"<40-character Git commit>","scenarioDigest":"sha256:<64 lowercase hexadecimal characters>","scenarioOutcomes":{"<scenario-id>":{"environment":"fixture|chromium|built-linux","status":"pass|linux-required"}}}
```

The source commit and canonical scenario digest make two runs from the same clean commit byte-identical. Every scenario has an explicit result. A portable macOS run reports each Linux addition as `linux-required`; it does not pretend those tests ran. The required Linux CI lane must report those same scenarios as `pass`. Diagnostics use stable stage names on stderr. Private errors, paths, assertions, cookies, acknowledgement proof, executor binding, and provider details are never copied into this result.

Run this portable command during implementation and pull-request verification. The public pull-request affected-check route already selects this browser group for Phase 4, browser, schema, workflow, or verifier changes.

The stronger `pnpm check:phase-4-exit --commit <exact-main-sha>` certificate runs only on Linux and requires the clean checkout's `HEAD` and trusted `refs/remotes/origin/main` to equal the supplied commit before and after verification. It rejects a feature branch and a portable result with `linux-required` scenarios. After merge, the trusted `main` push supplies the first exact run; an explicit `workflow_dispatch` at the unchanged same `main` commit supplies the second. Compare their JSON lines exactly, including the evidence digest. Do not record operator acceptance before both exact default-branch runs pass.

## Failure and recovery

A failed scenario returns a nonzero exit and a stable `Phase 4 verification failed at <stage>` diagnostic. Browser output is scanned before removal even after a test failure. A deterministic product failure belongs to its owning Phase 4 issue; do not weaken, skip, retry, or quarantine the required scenario inside this suite.

The fixtures prove development behavior only. They do not satisfy live Slack, provider, host, release, deployment, backup, or fleet gates. Full supported-OS and browser breadth remains Phase 11 work.
