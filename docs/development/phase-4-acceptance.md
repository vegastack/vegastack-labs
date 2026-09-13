# Phase 4 acceptance

`pnpm check:phase-4` is the credential-free acceptance command for declarations, immutable plans, authorization, Slack acknowledgement, durable runs, external executor leases, browser recovery, and private-data exclusion.

The command uses only generated contracts and isolated fixtures. It does not contact Slack, a provider, a managed host, or the inventory fleet, and it grants no release or deployment authority.

## What the command proves

The verifier reads the closed scenario list in `tooling/testdata/phase-4/acceptance-scenarios.json` and requires every scenario listed by `tooling/phase-4-evidence.json`. Each entry points to a real test or browser proof in the repository. Missing files, missing selectors, changed ordering, duplicate IDs, unknown environments, or any quarantined scenario fail before execution.

On every supported development host it:

1. verifies the generated contracts, built CLI boundary, static Console, and closed acceptance definition;
2. builds the Console unless the parent check already built it;
3. drives the generated browser client through exact plan display and checks that protected acknowledgement, executor, provider, and SQLite paths never enter the browser; and
4. scans retained browser output with the existing bounded artifact sanitizer.

On Linux it additionally:

1. runs the Phase 4 adapter, acknowledgement, API, authorization, CLI, plan, run, and SQLite packages with the race detector;
2. builds the real `vsk-labs` executable with the temporary database and Debian release fixture bound at link time;
3. launches `vsk-labs server run` against an authoritative temporary SQLite database and real loopback TLS; and
4. exercises the server-owned Slack fixture, local typed adapter, interruption, resume, cancellation, external executor, receipt, and recovery paths.

The production adapter registry stays empty. Test adapters and synthetic identities exist only in test files and cannot be selected by a normal build.

## Deterministic result

A successful run writes one JSON line to stdout:

```json
{"schemaVersion":1,"check":"phase-4","status":"pass","sourceCommit":"<40-character Git commit>","scenarioDigest":"sha256:<64 lowercase hexadecimal characters>"}
```

The source commit and canonical scenario digest make two runs from the same clean commit byte-identical. Diagnostics use stable stage names on stderr. Private errors, paths, assertions, cookies, acknowledgement proof, executor binding, and provider details are never copied into this result.

Run the command twice from the clean candidate commit, compare the two lines exactly, then run `pnpm check`. The public pull-request affected-check route already selects this browser group for Phase 4, browser, schema, workflow, or verifier changes. The exact `main` exit route runs the same catalog inside the Phase 3 exact-commit check before accepting the integrated commit.

## Failure and recovery

A failed scenario returns a nonzero exit and a stable `Phase 4 verification failed at <stage>` diagnostic. Browser output is scanned before removal even after a test failure. A deterministic product failure belongs to its owning Phase 4 issue; do not weaken, skip, retry, or quarantine the required scenario inside this suite.

The fixtures prove development behavior only. They do not satisfy live Slack, provider, host, release, deployment, backup, or fleet gates. Full supported-OS and browser breadth remains Phase 11 work.
